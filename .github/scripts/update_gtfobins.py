#!/usr/bin/env python3
"""Sync suid3num.py's GTFObins data from live GTFObins.

Runs in CI only (needs network + PyYAML). It NEVER changes suid3num.py's logic,
only its GTFObins-derived data:

  * gtfoBinsSuidsList  -> fully regenerated from upstream (sorted).
  * customSUIDs        -> append-only; a new suid binary is added only when it is
                          absent from BOTH customSUIDs and suidExploitation.

That append-only rule preserves the invariant suid3num.py relies on at the
"Manual Exploitation" step: every gtfo suid binary not in suidExploitation must
be a customSUIDs key, otherwise the tool hits a KeyError. Existing hand-tuned
entries are left untouched, so diffs stay small and reviewable.

ponytail: raw upstream suid code for new entries; no attempt to replay the old
./bin + -p styling. suid3num.py's display already strips "./" and substitutes
the real path, so raw code works. Hand-polish in review if desired.
"""

import ast
import json
import re
import sys
import urllib.request

REPO = "GTFOBins/GTFOBins.github.io"
TREE_URL = "https://api.github.com/repos/%s/git/trees/master?recursive=1" % REPO
RAW = "https://raw.githubusercontent.com/%s/master/" % REPO
TARGET = "suid3num.py"


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "suid3num-bot"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8")


def fetch_suid_bins():
    """Return {name: suid_code} for every GTFObins entry exposing a suid context."""
    import yaml  # imported here so --help etc. works without the dep

    tree = json.loads(_get(TREE_URL))["tree"]
    paths = [n["path"] for n in tree if n["path"].startswith("_gtfobins/")]

    parsed = {}
    for path in paths:
        name = path.split("/", 1)[1]
        if "." in name:  # skip old-version files like foo.md
            continue
        parsed[name] = yaml.safe_load(_get(RAW + path)) or {}

    suid = {}
    for name, data in parsed.items():
        # Aliases carry no functions of their own; resolve to the target entry.
        target = data
        seen = set()
        while target.get("alias") and target["alias"] in parsed and target["alias"] not in seen:
            seen.add(target["alias"])
            target = parsed[target["alias"]]
        code = suid_code(target)
        if code is not None:
            suid[name] = code
    return suid


def suid_code(data):
    """Extract the suid example code from a parsed gtfobin, or None."""
    for examples in (data.get("functions") or {}).values():
        for example in examples or []:
            contexts = example.get("contexts")
            # No contexts means it defaults to the first context (unprivileged).
            if not contexts or "suid" not in contexts:
                continue
            override = contexts["suid"]
            if isinstance(override, dict) and override.get("code"):
                return override["code"].strip()
            return (example.get("code") or "").strip()
    return None


def dict_keys(tree, name):
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            getattr(t, "id", None) == name for t in node.targets
        ):
            return {ast.literal_eval(k) for k in node.value.keys}
    raise SystemExit("could not find dict %s" % name)


def main():
    src = open(TARGET, encoding="utf-8").read()
    tree = ast.parse(src)
    existing_custom = dict_keys(tree, "customSUIDs")
    existing_auto = dict_keys(tree, "suidExploitation")

    suid = fetch_suid_bins()
    if len(suid) < 100:  # sanity guard against a broken/empty upstream fetch
        raise SystemExit("only %d suid bins fetched; refusing to rewrite" % len(suid))

    names = sorted(suid)

    # 1) regenerate gtfoBinsSuidsList verbatim-formatted like the original.
    list_body = "".join('    "%s",\n' % n for n in names)
    new_list = "gtfoBinsSuidsList = [\n%s]" % list_body
    # lambda replacements bypass re's backslash processing, so \n / \t inside the
    # generated code survive as literal two-char escapes in the Python source.
    src, n = re.subn(
        r"gtfoBinsSuidsList = \[.*?\n\]", lambda _m: new_list, src,
        count=1, flags=re.DOTALL,
    )
    if n != 1:
        raise SystemExit("could not locate gtfoBinsSuidsList block")

    # 2) append-only new customSUIDs entries so the KeyError invariant holds.
    additions = [n for n in names if n not in existing_custom and n not in existing_auto]
    if additions:
        block = "".join("    %r: %r,\n" % (n, suid[n]) for n in additions)
        src, n = re.subn(
            r"(customSUIDs = \{.*?)(\n\})",
            lambda m: m.group(1) + "\n" + block.rstrip("\n") + m.group(2),
            src, count=1, flags=re.DOTALL,
        )
        if n != 1:
            raise SystemExit("could not locate customSUIDs block")

    if "--dry-run" in sys.argv:
        print("suid bins: %d | new customSUIDs entries: %d" % (len(names), len(additions)))
        for a in additions:
            print("  + %s" % a)
        return

    open(TARGET, "w", encoding="utf-8").write(src)
    print("updated %s: %d suid bins, %d new entries" % (TARGET, len(names), len(additions)))


if __name__ == "__main__":
    main()
