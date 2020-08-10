# SUID3NUM

[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/commit-activity)
[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
[![python](https://img.shields.io/badge/python-2-blue.svg)](https://www.python.org/downloads/)
[![python](https://img.shields.io/badge/python-3-blue.svg)](https://www.python.org/downloads/)
[![Open Source Love](https://badges.frapsoft.com/os/mit/mit.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)
[![Twitter](https://img.shields.io/twitter/url/https/twitter.com/cloudposse.svg?style=social&label=%40syed_umar)](https://twitter.com/syed__umar)


**A standalone python2/3 script which utilizes python's built-in modules to find SUID bins, separate default bins from custom bins, cross-match those with bins in GTFO Bin's repository & auto-exploit those, all with colors! ( ͡ʘ ͜ʖ ͡ʘ)**

[![asciicast](https://asciinema.org/a/343568.svg)](https://asciinema.org/a/343568)

### Description
A standalone script supporting both python2 & python3 to find out all SUID binaries in machines/CTFs and do the following
- List all Default SUID Binaries (which ship with linux/aren't exploitable)
- List all Custom Binaries (which don't ship with packages/vanilla installation)
- List all custom binaries found in GTFO Bin's (This is where things get interesting)
- Printing binaries and their exploitation (in case they create files on the machine)
- Try and exploit found custom SUID binaries which won't impact machine's files

Why This? 
- Because LinEnum and other enumeration scripts only print SUID binaries & GTFO Binaries, they don't seperate default from custom, which leads to severe head banging in walls for 3-4 hours when you can't escalate privs :) 

### Can I use this in OSCP?
Yes, you totally can. I used it in my exam, linked it in the report as well. Just don't use `-e` (according to some people) and you're good to go!

### Changelog
- Added new section of binaries which impact the system (Auto-Exploitation isn't supported for binaries which impact the system in any way i.e. creating new files, directories, modifying existing files etc.). The user has to manually execute those commands, and is supposed to understand those before running as well! (POC: 
https://i.imgur.com/FclFFwg.png)

### Output
<a href="https://github.com/Anon-Exploiter/SUID3NUM/blob/master/output.matlab" target="_blank">SUID3NUM's Sample output</a>

### Works on 

- Python (2.5-7.*)
- Python (3.5-7.*)

### Download & Use

	wget https://raw.githubusercontent.com/Anon-Exploiter/SUID3NUM/master/suid3num.py --no-check-certificate && chmod 777 suid3num.py
	curl -k https://raw.githubusercontent.com/Anon-Exploiter/SUID3NUM/master/suid3num.py --output suid3num.py && chmod 777 suid3num.py
	
### Tested on

- Pop! OS 18.04 LTS
- Ubuntu 18.04 LTS
- Nebula
- Kali Linux (PWK VM)
 
### Usage

***Initializing Script***

	python suid3num.py

***Doing Auto Exploitation of found custom SUID binaries***

	python suid3num.py -e

### Output

<img src="https://i.imgur.com/zaDb93l.png" />
<img src="https://i.imgur.com/XOqNsjq.png" />
<img src="https://i.imgur.com/2skqTXo.png" />
<img src="https://i.imgur.com/gBabtgR.png" />
<img src="https://i.imgur.com/GCLgIOO.png" />

### Auto Exploitation of SUID Bins

[![asciicast](https://asciinema.org/a/343572.svg)](https://asciinema.org/a/343572)

### Note 
<pre><code>Please run the script after going through what it does & with prior knowledge of SUID bins.
P.S ~ Don't run with `-e` parameter, if you don't know what you're doing!
</code></pre>

### Stargazers Chart
[![Stargazers over time](https://starchart.cc/Anon-Exploiter/SUID3NUM.svg)](https://starchart.cc/Anon-Exploiter/SUID3NUM)

### Shoutouts
Shoutout to [Zeeshan Sahi](https://www.linkedin.com/in/zeeshan-sahi-366238117/) & [Bilal Rizwan](https://github.com/th3-3inst3in) for their ideas and contribution. Also, thanks to [Cyrus](https://github.com/cyrus-and) for [GTFO Bins](https://gtfobins.github.io/) <3

Let me know, what you think of this script at [@syed__umar](https://twitter.com/@syed__umar) ≧◡≦
