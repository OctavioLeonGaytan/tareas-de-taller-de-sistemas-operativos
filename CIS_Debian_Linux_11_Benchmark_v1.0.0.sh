#! /bin/bash
##########################################
#####Autor: Octavio Josue Leon Gaytan#####
##########################################
###CIS Debian Linux 11 Benchmark v1.0.0###
##########################################
###Pasos para iniciar este archivo########
#Iniciar en la terminal como usuario root#
#Darle permisos al archivo chmod +x {archivo}
#ejecutar ./{archivo}#####################


#1 Initial Setup#
##########################################

#1.1 Filesystem configuration#
##########################################
#1.1.1 Disable unused filesystems#########
#1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Automated) 
#1.1.1.2 Ensure mounting of squashfs filesystems is disabled (Automated) 
#1.1.1.3 Ensure mounting of udf filesystems is disabled (Automated)

echo "install cramfs /bin/true
install squashfs /bin/true
install udf /bin/true" > /etc/modprobe.d/CIS.conf


##set_directive_fs "install udf /bin/true" "rmmod udf" /etc/modprobe.d/udf.conf       ver si jala


##########################################
#1.1.2 Configure /tmp######################
#1.1.2.1 Ensure /tmp is a separate partition (Automated)
#1.1.2.2 Ensure nodev option set on /tmp partition (Automated) 
#1.1.2.3 Ensure noexec option set on /tmp partition (Automated) 
#1.1.2.4 Ensure nosuid option set on /tmp partition (Automated) 

sed -i '/ \/tmp/s/defaults/defaults,nodev,nosuid,noexec/g' /etc/fstab

##########################################
#1.1.3 Configure /var######################
#1.1.3.1 Ensure separate partition exists for /var (Automated)
#1.1.3.2 Ensure nodev option set on /var partition (Automated) 
#1.1.3.3 Ensure nosuid option set on /var partition (Automated) 

sed -i '/\/var\/tmp/s/defaults/defaults,nodev,nosuid/g' /etc/fstab

##########################################
#1.1.4 Configure /var/tmp #################
#1.1.4.1 Ensure separate partition exists for /var/tmp (Automated) 
#1.1.4.2 Ensure noexec option set on /var/tmp partition (Automated) 
#1.1.4.3 Ensure nosuid option set on /var/tmp partition (Automated) 
#1.1.4.4 Ensure nodev option set on /var/tmp partition (Automated)

##sed -i '/\/var\/tmp/s/defaults/defaults,noexec,nosuid,nodev/g' /etc/fstab  sino funciona los de abajo

if sed -n '/ \/tmp/p' /etc/fstab | grep 'noexec'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/ \/tmp/s/defaults/defaults,noexec/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
if sed -n '/ \/tmp/p' /etc/fstab | grep 'nosuid'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/ \/tmp/s/defaults/defaults,nosuid/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
if sed -n '/ \/tmp/p' /etc/fstab | grep 'nodev'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/ \/tmp/s/defaults/defaults,nodev/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi


##########################################
#1.1.5 Configure /var/log##################
#1.1.5.1 Ensure separate partition exists for /var/log (Automated) 
#1.1.5.2 Ensure nodev option set on /var/log partition (Automated) 
#1.1.5.3 Ensure noexec option set on /var/log partition (Automated)
#1.1.5.4 Ensure nosuid option set on /var/log partition (Automated)

sed -i '/\/var\/log/s/defaults/defaults,nodev,noexec,nosuid/g' /etc/fstab

##########################################
#1.1.6 Configure /var/log/audit############
#1.1.6.1 Ensure separate partition exists for /var/log/audit (Automated)
#1.1.6.2 Ensure noexec option set on /var/log/audit partition (Automated)
#1.1.6.3 Ensure nodev option set on /var/log/audit partition (Automated)
#1.1.6.4 Ensure nosuid option set on /var/log/audit partition (Automated)

sed -i '/\/var\/log/audit/defaults/defaults,nodev,nosuid,noexec/g' /etc/fstab

##########################################
#1.1.7 Configure /home#####################
#1.1.7.1 Ensure separate partition exists for /home (Automated) 
#1.1.7.2 Ensure nodev option set on /home partition (Automated) 
#1.1.7.3 Ensure nosuid option set on /home partition (Automated) 

if sed -n '/\/home/p' /etc/fstab | grep 'nodev'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/\/home/s/defaults/defaults,nodev/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
if sed -n '/\/home/p' /etc/fstab | grep 'nosuid'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/\/home/s/defaults/defaults,nosuid/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi

##sed -i '/\/home/s/defaults/defaults,nodev/g' /etc/fstab
##sed -i '/\/home/s/defaults/defaults,nosuid/g' /etc/fstab

##########################################
#1.1.8 Configure /dev/shm##################
#1.1.8.1 Ensure nodev option set on /dev/shm partition (Automated)
#1.1.8.2 Ensure noexec option set on /dev/shm partition (Automated)
#1.1.8.3 Ensure nosuid option set on /dev/shm partition (Automated)
#1.1.9 Disable Automounting (Automated)
#1.1.10 Disable USB Storage (Automated)

if sed -n '/\/dev\/shm/p' /etc/fstab | grep 'nodev'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/\/dev\/shm/s/defaults/defaults,nodev/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
if sed -n '/\/dev\/shm/p' /etc/fstab | grep 'noexec'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/\/dev\/shm/s/defaults/defaults,noexec/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi
if sed -n '/\/dev\/shm/p' /etc/fstab | grep 'nosuid'; then echo -e '\e[1;32mIt was already configured\e[0m'; else sed -i '/\/dev\/shm/s/defaults/defaults,nosuid/g' /etc/fstab; echo -e '\e[1;32mDone\e[0m'; fi

##########################################
#1.2 Configure Software Updates############
#1.2.1 Ensure package manager repositories are configured (Manual)
#1.2.2 Ensure GPG keys are configured (Manual) 

apt-cache policy
apt-key list

##########################################
#1.3 Filesystem Integrity Checking#########
#1.3.1 Ensure AIDE is installed (Automated)
#1.3.2 Ensure filesystem integrity is regularly checked (Automated)

sudo apt install aide aide-common

##########################################
#1.4 Secure Boot Settings##################
#1.4.1 Ensure bootloader password is set (Automated)
#1.4.2 Ensure permissions on bootloader config are configured (Automated)
#1.4.3 Ensure authentication required for single user mode (Automated) 

echo "cat <<EOF
set superusers=\"anakin\"
password_pbkdf2 anakin grub.pbkdf2.sha512.10000.98CEB6403454C099D2A55995595519E3173D2075ACAA673F097E53789C8484B6E677E6582C3D278ACF68AD53F573E5E2BF115F97B41173C0BFB2646A597384E4.0C894BEDC392047BD3C7309FD1FD048088D53990D9B360227E7BC4FFDA37A9FB42CDD2FE263567CD5ED2A03A7EC3018233801221DE7647878949DEA4759437AE
EOF" >> /etc/grub.d/01_users
update-grub


chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

##########################################
#1.5 Additional Process Hardening #########
#1.5.1 Ensure address space layout randomization (ASLR) is enabled (Automated)
#1.5.2 Ensure prelink is not installed (Automated)
#1.5.3 Ensure Automatic Error Reporting is not enabled (Automated) 
#1.5.4 Ensure core dumps are restricted (Automated) 

set_directive "kernel.randomize_va_space" 2 "/etc/sysctl.conf";
sysctl -w kernel.randomize_va_space=2

prelink -ua
apt purge prelink

 grep -Es '^(\*|\s).*hard.*core.*(\s+#.*)?$' /etc/security/limits.conf 
/etc/security/limits.d/*

sysctl fs.suid_dumpable

grep "fs.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*


#########################################
#1.6 Mandatory Access Control ############
#1.6.1 Configure AppArmor#################
#1.6.1.1 Ensure AppArmor is installed (Automated) 
#1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration (Automated)
#1.6.1.3 Ensure all AppArmor Profiles are in enforce or complain mode (Automated)
#1.6.1.4 Ensure all AppArmor Profiles are enforcing (Automated)

apt install apparmor apparmor-utils

sed -i '/^GRUB_CMDLINE_LINUX=/ c GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"' /etc/default/grub

aa-enforce /etc/apparmor.d/*

aa-complain /etc/apparmor.d/*

aa-enforce /etc/apparmor.d/*

#########################################
#1.7 Command Line Warning Banners ########
#1.7.1 Ensure message of the day is configured properly (Automated)
#1.7.2 Ensure local login warning banner is configured properly (Automated) 
#1.7.3 Ensure remote login warning banner is configured properly (Automated)
#1.7.4 Ensure permissions on /etc/motd are configured (Automated) 
#1.7.5 Ensure permissions on /etc/issue are configured (Automated)
#1.7.6 Ensure permissions on /etc/issue.net are configured (Automated)

##rm /etc/motd si no se ocupa puede ser removido
#echo "******************************************
#* This is an $COMPANY system, restricted      *
#* to authorized individuals. This system *
#* is subject to monitoring. By logging   *
#* into this system you agree to have all *
#* your communications monitored.         *
#* Unauthorized users, access, and/or     *
#* modification will be prosecuted.       *
#******************************************" > /etc/motd

# echo "Authorized uses only. All activity may be monitored and reported." > 
#/etc/issue

# echo "Authorized uses only. All activity may be monitored and reported." > 
#/etc/issue.net

#chown root:root $(readlink -e /etc/motd)
#chmod u-x,go-wx $(readlink -e /etc/motd)

#chown root:root $(readlink -e /etc/issue)
#chmod u-x,go-wx $(readlink -e /etc/issue)

#chown root:root $(readlink -e /etc/issue.net)
#chmod u-x,go-wx $(readlink -e /etc/issue.net)


#########################################     
#1.8 GNOME Display Manager################
#1.8.1 Ensure GNOME Display Manager is removed (Automated)
#1.8.2 Ensure GDM login banner is configured (Automated)
#1.8.3 Ensure GDM disable-user-list option is enabled (Automated)
#1.8.4 Ensure GDM screen locks when the user is idle (Automated) 
#1.8.5 Ensure GDM screen locks cannot be overridden (Automated) 
#1.8.6 Ensure GDM automatic mounting of removable media is disabled (Automated) 
#1.8.7 Ensure GDM disabling automatic mounting of removable media is not overridden (Automated)
#1.8.8 Ensure GDM autorun-never is enabled (Automated)
#1.8.9 Ensure GDM autorun-never is not overridden (Automated)
#1.8.10 Ensure XDCMP is not enabled (Automated)
#1.9 Ensure updates, patches, and additional security software are installed (Manual)

#apt purge gdm3

#########################################
#2.1.2 Configure chrony ##################
#2.1.2.1 Ensure chrony is configured with authorized timeserver (Manual)
#2.1.2.2 Ensure chrony is running as user _chrony (Automated) 
#2.1.2.3 Ensure chrony is enabled and running (Automated) 

apt install chrony

systemctl stop systemd-timesyncd.service
systemctl --now mask systemd-timesyncd.service

apt purge ntp

#########################################
#2.2 Special Purpose Services ############   
#2.2.1 Ensure X Window System is not installed (Automated)    
#2.2.2 Ensure Avahi Server is not installed (Automated)     
#2.2.3 Ensure CUPS is not installed (Automated)     
#2.2.4 Ensure DHCP Server is not installed (Automated)  
#2.2.5 Ensure LDAP server is not installed (Automated)  
#2.2.6 Ensure NFS is not installed (Automated)       
#2.2.7 Ensure DNS Server is not installed (Automated)      
#2.2.8 Ensure FTP Server is not installed (Automated)     
#2.2.9 Ensure HTTP server is not installed (Automated)    
#2.2.10 Ensure IMAP and POP3 server are not installed (Automated)
#2.2.11 Ensure Samba is not installed (Automated)         
#2.2.12 Ensure HTTP Proxy Server is not installed (Automated) 
#2.2.13 Ensure SNMP Server is not installed (Automated)     
#2.2.14 Ensure NIS Server is not installed (Automated)    
#2.2.15 Ensure mail transfer agent is configured for local-only mode (Automated)    
#2.2.16 Ensure rsync service is either not installed or masked (Automated)

apt purge xserver-xorg*

systemctl stop avahi-daaemon.service
systemctl stop avahi-daemon.socket
apt purge avahi-daemon

apt purge cups

apt purge isc-dhcp-server

apt purge slapd

apt purge bind9

apt purge vsftpd

apt purge apache2

apt purge dovecot-imapd dovecot-pop3d

apt purge samba

apt purge squid

apt purge snmp

apt purge nis

file="/etc/postfix/main.cf"
if [ ! -e $file ]; then echo -e '\e[1;31m'$file' not found.\e[0m'; else sed -i /'^inet_interfaces/ c inet_interfaces = loopback-only' $file; fi

systemctl restart postfix

apt purge rsync


#########################################
#2.3 Service Clients######################       
#2.3.1 Ensure NIS Client is not installed (Automated)   
#2.3.2 Ensure rsh client is not installed (Automated)     
#2.3.3 Ensure talk client is not installed (Automated)     
#2.3.4 Ensure telnet client is not installed (Automated)    
#2.3.5 Ensure LDAP client is not installed (Automated)    
#2.3.6 Ensure RPC is not installed (Automated)    
#2.4 Ensure nonessential services are removed or masked (Manual)

apt purge nis

apt purge rsh-client

apt purge talk

apt purge telnet

apt purge ldap-utils

apt purge rpcbind

apt purge <package_name>

 
#########################################
#3 Network Configuration##################   
#3.1 Disable unused network protocols and devices###############  
#3.1.1 Ensure system is checked to determine if IPv6 is enabled (Manual)
#3.1.2 Ensure wireless interfaces are disabled (Automated)  
#3.1.3 Ensure DCCP is disabled (Automated)   
#3.1.4 Ensure SCTP is disabled (Automated)   
#3.1.5 Ensure RDS is disabled (Automated)    
#3.1.6 Ensure TIPC is disabled (Automated)

GRUB_CMDLINE_LINUX="ipv6.disable=1"
update-grub

#!/bin/bash
if command -v nmcli >/dev/null 2>&1 ; then
 nmcli radio all off
else
 if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
 mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless 
| xargs -0 dirname); do basename "$(readlink -f 
"$driverdir"/device/driver/module)";done | sort -u)
 for dm in $mname; do
 echo "install $dm /bin/true" >> /etc/modprobe.d/disable_wireless.conf
 done
 fi
fi

#!/usr/bin/env bash
{
 l_mname="dccp" # set module name
 # Check if the module exists on the system
 if [ -z "$(modprobe -n -v "$l_mname" 2>&1 | grep -Pi --
"\h*modprobe:\h+FATAL:\h+Module\h+$l_mname\h+not\h+found\h+in\h+directory")" 
]; then
 # Remediate loadable
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; 
then
 echo -e " - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> 
/etc/modprobe.d/"$l_mname".conf
 fi
 # Remediate loaded
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e " - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 # Remediate deny list
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$(tr '-' '_' 
<<< "$l_mname")\b"; then
 echo -e " - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
 fi
 else
 echo -e " - Nothing to remediate\n - Module \"$l_mname\" doesn't exist 
on the system"
 fi
}

#!/usr/bin/env bash
{
 l_mname="sctp" # set module name
 # Check if the module exists on the system
 if [ -z "$(modprobe -n -v "$l_mname" 2>&1 | grep -Pi --
"\h*modprobe:\h+FATAL:\h+Module\h+$l_mname\h+not\h+found\h+in\h+directory")" 
]; then
 # Remediate loadable
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; 
then
 echo -e " - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> 
/etc/modprobe.d/"$l_mname".conf
 fi
 # Remediate loaded
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e " - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 # Remediate deny list
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mname\b"; 
then
 echo -e " - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
 fi
 else
 echo -e " - Nothing to remediate\n - Module \"$l_mname\" doesn't exist 
on the system"
 fi
}

#!/usr/bin/env bash
{
 l_mname="rds" # set module name
 # Check if the module exists on the system
 if [ -z "$(modprobe -n -v "$l_mname" 2>&1 | grep -Pi --
"\h*modprobe:\h+FATAL:\h+Module\h+$l_mname\h+not\h+found\h+in\h+directory")" 
]; then
 # Remediate loadable
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; 
then
 echo -e " - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> 
/etc/modprobe.d/"$l_mname".conf
 fi
 # Remediate loaded
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e " - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 # Remediate deny list
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mname\b"; 
then
 echo -e " - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
 fi
 else
 echo -e " - Nothing to remediate\n - Module \"$l_mname\" doesn't exist 
on the system"
 fi
}

#!/usr/bin/env bash
{
 l_mname="tipc" # set module name
 # Check if the module exists on the system
 if [ -z "$(modprobe -n -v "$l_mname" 2>&1 | grep -Pi --
"\h*modprobe:\h+FATAL:\h+Module\h+$l_mname\h+not\h+found\h+in\h+directory")" 
]; then
 # Remediate loadable
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; 
then
 echo -e " - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> 
/etc/modprobe.d/"$l_mname".conf
 fi
 # Remediate loaded
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e " - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 # Remediate deny list
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mname\b"; 
then
 echo -e " - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
 fi
 else
 echo -e " - Nothing to remediate\n - Module \"$l_mname\" doesn't exist 
on the system"
 fi
}

########################################
#3.2 Network Parameters (Host Only)###### 
#3.2.1 Ensure packet redirect sending is disabled (Automated)   
#3.2.2 Ensure IP forwarding is disabled (Automated)

#!/usr/bin/env bash
{
 l_output="" l_output2=""
 l_parlist="net.ipv4.conf.all.send_redirects=0 
net.ipv4.conf.default.send_redirects=0"
 l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf 
/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf 
/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ 
{print $2}' /etc/default/ufw)"
 l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
 KPF()
 { 
 # comment out incorrect parameter(s) in kernel parameter file(s)
 l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv --
"\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
 for l_bkpf in $l_fafile; do
 echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
 sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
 done
 # Set correct parameter in a kernel parameter file
 if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" 
$l_searchloc; then
 echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in 
\"$l_kpfile\""
 echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
 fi
 # Set correct parameter in active kernel parameters
 l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
 if [ "$l_krp" != "$l_kpvalue" ]; then
 echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active 
kernel parameters"
 sysctl -w "$l_kpname=$l_kpvalue"
 sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< 
"$l_kpname")"
 fi
 }
 for l_kpe in $l_parlist; do
 l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")" 
 l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")" 
 KPF
 done
}


#!/usr/bin/env bash
{
 l_output="" l_output2=""
 l_parlist="net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0"
 l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf 
/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf 
/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ 
{print $2}' /etc/default/ufw)"
 KPF()
 { 
 # comment out incorrect parameter(s) in kernel parameter file(s)
 l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv --
"\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
 for l_bkpf in $l_fafile; do
 echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
 sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
 done
 # Set correct parameter in a kernel parameter file
 if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" 
$l_searchloc; then
 echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in 
\"$l_kpfile\""
 echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
 fi
 # Set correct parameter in active kernel parameters
 l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
 if [ "$l_krp" != "$l_kpvalue" ]; then
 echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active 
kernel parameters"
 sysctl -w "$l_kpname=$l_kpvalue"
 sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< 
"$l_kpname")"
 fi
 }
 IPV6F_CHK()
 {
 l_ipv6s=""
 grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -
o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} 
\;)
 if [ -s "$grubfile" ]; then
 ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq 
-- ipv6.disable=1 && l_ipv6s="disabled"
 fi
 if grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
 grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc 
&& \
 sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
 sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
 l_ipv6s="disabled"
 fi
 if [ -n "$l_ipv6s" ]; then
Page 318
 echo -e "\n - IPv6 is disabled on the system, \"$l_kpname\" is not 
applicable"
 else
 KPF
 fi
 }
 for l_kpe in $l_parlist; do
 l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")" 
 l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")" 
 if grep -q '^net.ipv6.' <<< "$l_kpe"; then
 l_kpfile="/etc/sysctl.d/60-netipv6_sysctl.conf"
 IPV6F_CHK
 else
 l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
 KPF
 fi
 done
}



########################################
#3.3 Network Parameters (Host and Router)############  
#3.3.1 Ensure source routed packets are not accepted (Automated)  
#3.3.2 Ensure ICMP redirects are not accepted (Automated)   
#3.3.3 Ensure secure ICMP redirects are not accepted (Automated)    
#3.3.4 Ensure suspicious packets are logged (Automated)    
#3.3.5 Ensure broadcast ICMP requests are ignored (Automated)     
#3.3.6 Ensure bogus ICMP responses are ignored (Automated) 
#3.3.7 Ensure Reverse Path Filtering is enabled (Automated)   
#3.3.8 Ensure TCP SYN Cookies is enabled (Automated)      
#3.3.9 Ensure IPv6 router advertisements are not accepted (Automated)

#!/usr/bin/env bash
{
 l_output="" l_output2=""
 l_parlist="net.ipv4.conf.all.accept_source_route=0 
net.ipv4.conf.default.accept_source_route=0 
net.ipv6.conf.all.accept_source_route=0 
net.ipv6.conf.default.accept_source_route=0"
 l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf 
/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf 
/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ 
{print $2}' /etc/default/ufw)"
 KPF()
 { 
 # comment out incorrect parameter(s) in kernel parameter file(s)
 l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv --
"\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
 for l_bkpf in $l_fafile; do
 echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
 sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
 done
 # Set correct parameter in a kernel parameter file
 if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" 
$l_searchloc; then
 echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in 
\"$l_kpfile\""
 echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
 fi
 # Set correct parameter in active kernel parameters
 l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
 if [ "$l_krp" != "$l_kpvalue" ]; then
 echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active 
kernel parameters"
 sysctl -w "$l_kpname=$l_kpvalue"
 sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< 
"$l_kpname")"
 fi
 }
 IPV6F_CHK()
 {
 l_ipv6s=""
 grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -
o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} 
\;)
 if [ -s "$grubfile" ]; then
 ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq 
-- ipv6.disable=1 && l_ipv6s="disabled"
 fi
 if grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
 grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc 
&& \
 sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
 sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
Page 325
 l_ipv6s="disabled"
 fi
 if [ -n "$l_ipv6s" ]; then
 echo -e "\n - IPv6 is disabled on the system, \"$l_kpname\" is not 
applicable"
 else
 KPF
 fi
 }
 for l_kpe in $l_parlist; do
 l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")" 
 l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")" 
 if grep -q '^net.ipv6.' <<< "$l_kpe"; then
 l_kpfile="/etc/sysctl.d/60-netipv6_sysctl.conf"
 IPV6F_CHK
 else
 l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
 KPF
 fi
 done
}


#!/usr/bin/env bash
{
 l_output="" l_output2=""
 l_parlist="net.ipv4.conf.all.accept_redirects=0 
net.ipv4.conf.default.accept_redirects=0 net.ipv6.conf.all.accept_redirects=0 
net.ipv6.conf.default.accept_redirects=0"
 l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf 
/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf 
/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ 
{print $2}' /etc/default/ufw)"
 KPF()
 { 
 # comment out incorrect parameter(s) in kernel parameter file(s)
 l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv --
"\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
 for l_bkpf in $l_fafile; do
 echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
 sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
 done
 # Set correct parameter in a kernel parameter file
 if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" 
$l_searchloc; then
 echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in 
\"$l_kpfile\""
 echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
 fi
 # Set correct parameter in active kernel parameters
 l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
 if [ "$l_krp" != "$l_kpvalue" ]; then
 echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active 
kernel parameters"
 sysctl -w "$l_kpname=$l_kpvalue"
 sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< 
"$l_kpname")"
 fi
 }
 IPV6F_CHK()
 {
 l_ipv6s=""
 grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -
o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} 
\;)
 if [ -s "$grubfile" ]; then
 ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq 
-- ipv6.disable=1 && l_ipv6s="disabled"
 fi
 if grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
 grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc 
&& \
 sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
 sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
 l_ipv6s="disabled"
Page 331
 fi
 if [ -n "$l_ipv6s" ]; then
 echo -e "\n - IPv6 is disabled on the system, \"$l_kpname\" is not 
applicable"
 else
 KPF
 fi
 }
 for l_kpe in $l_parlist; do
 l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")" 
 l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")" 
 if grep -q '^net.ipv6.' <<< "$l_kpe"; then
 l_kpfile="/etc/sysctl.d/60-netipv6_sysctl.conf"
 IPV6F_CHK
 else
 l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
 KPF
 fi
 done
}



#!/usr/bin/env bash
{
 l_output="" l_output2=""
 l_parlist="net.ipv4.conf.default.secure_redirects=0 
net.ipv4.conf.all.secure_redirects=0"
 l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf 
/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf 
/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ 
{print $2}' /etc/default/ufw)"
 l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
 KPF()
 { 
 # comment out incorrect parameter(s) in kernel parameter file(s)
 l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv --
"\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
 for l_bkpf in $l_fafile; do
 echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
 sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
 done
 # Set correct parameter in a kernel parameter file
 if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" 
$l_searchloc; then
 echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in 
\"$l_kpfile\""
 echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
 fi
 # Set correct parameter in active kernel parameters
 l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
 if [ "$l_krp" != "$l_kpvalue" ]; then
 echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active 
kernel parameters"
 sysctl -w "$l_kpname=$l_kpvalue"
 sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< 
"$l_kpname")"
 fi
 }
 for l_kpe in $l_parlist; do
 l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")" 
 l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")" 
 KPF
 done
}



#!/usr/bin/env bash
{
 l_output="" l_output2=""
 l_parlist="net.ipv4.conf.all.log_martians=1 
net.ipv4.conf.default.log_martians=1"
 l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf 
/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf 
/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ 
{print $2}' /etc/default/ufw)"
 l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
 KPF()
 { 
 # comment out incorrect parameter(s) in kernel parameter file(s)
 l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv --
"\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
 for l_bkpf in $l_fafile; do
 echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
 sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
 done
 # Set correct parameter in a kernel parameter file
 if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" 
$l_searchloc; then
 echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in 
\"$l_kpfile\""
 echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
 fi
 # Set correct parameter in active kernel parameters
 l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
 if [ "$l_krp" != "$l_kpvalue" ]; then
 echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active 
kernel parameters"
 sysctl -w "$l_kpname=$l_kpvalue"
 sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< 
"$l_kpname")"
 fi
 }
 for l_kpe in $l_parlist; do
 l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")" 
 l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")" 
 KPF
 done
}



#!/usr/bin/env bash
{
 l_output="" l_output2=""
 l_parlist="net.ipv4.icmp_echo_ignore_broadcasts=1"
 l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf 
/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf 
/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ 
{print $2}' /etc/default/ufw)"
 l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
 KPF()
 { 
 # comment out incorrect parameter(s) in kernel parameter file(s)
 l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv --
"\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
 for l_bkpf in $l_fafile; do
 echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
 sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
 done
 # Set correct parameter in a kernel parameter file
 if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" 
$l_searchloc; then
 echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in 
\"$l_kpfile\""
 echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
 fi
 # Set correct parameter in active kernel parameters
 l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
 if [ "$l_krp" != "$l_kpvalue" ]; then
 echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active 
kernel parameters"
 sysctl -w "$l_kpname=$l_kpvalue"
 sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< 
"$l_kpname")"
 fi
 }
 for l_kpe in $l_parlist; do
 l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")" 
 l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")" 
 KPF
 done
}


#!/usr/bin/env bash
{
 l_output="" l_output2=""
 l_parlist="net.ipv4.icmp_ignore_bogus_error_responses=1"
 l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf 
/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf 
/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ 
{print $2}' /etc/default/ufw)"
 l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
 KPF()
 { 
 # comment out incorrect parameter(s) in kernel parameter file(s)
 l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv --
"\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
 for l_bkpf in $l_fafile; do
 echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
 sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
 done
 # Set correct parameter in a kernel parameter file
 if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" 
$l_searchloc; then
 echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in 
\"$l_kpfile\""
 echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
 fi
 # Set correct parameter in active kernel parameters
 l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
 if [ "$l_krp" != "$l_kpvalue" ]; then
 echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active 
kernel parameters"
 sysctl -w "$l_kpname=$l_kpvalue"
 sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< 
"$l_kpname")"
 fi
 }
 for l_kpe in $l_parlist; do
 l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")" 
 l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")" 
 KPF
 done
}



#!/usr/bin/env bash
{
 l_output="" l_output2=""
 l_parlist="net.ipv4.conf.all.rp_filter=1 
net.ipv4.conf.default.rp_filter=1"
 l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf 
/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf 
/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ 
{print $2}' /etc/default/ufw)"
 l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
 KPF()
 { 
 # comment out incorrect parameter(s) in kernel parameter file(s)
 l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv --
"\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
 for l_bkpf in $l_fafile; do
 echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
 sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
 done
 # Set correct parameter in a kernel parameter file
 if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" 
$l_searchloc; then
 echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in 
\"$l_kpfile\""
 echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
 fi
 # Set correct parameter in active kernel parameters
 l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
 if [ "$l_krp" != "$l_kpvalue" ]; then
 echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active 
kernel parameters"
 sysctl -w "$l_kpname=$l_kpvalue"
 sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< 
"$l_kpname")"
 fi
 }
 for l_kpe in $l_parlist; do
 l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")" 
 l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")" 
 KPF
 done
}



#!/usr/bin/env bash
{
 l_output="" l_output2=""
 l_parlist="net.ipv4.tcp_syncookies=1"
 l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf 
/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf 
/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ 
{print $2}' /etc/default/ufw)"
 l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
 KPF()
 { 
 # comment out incorrect parameter(s) in kernel parameter file(s)
 l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv --
"\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
 for l_bkpf in $l_fafile; do
 echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
 sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
 done
 # Set correct parameter in a kernel parameter file
 if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" 
$l_searchloc; then
 echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in 
\"$l_kpfile\""
 echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
 fi
 # Set correct parameter in active kernel parameters
 l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
 if [ "$l_krp" != "$l_kpvalue" ]; then
 echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active 
kernel parameters"
 sysctl -w "$l_kpname=$l_kpvalue"
 sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< 
"$l_kpname")"
 fi
 }
 for l_kpe in $l_parlist; do
 l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")" 
 l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")" 
 KPF
 done
}



#!/usr/bin/env bash
{
 l_output="" l_output2=""
 l_parlist="net.ipv6.conf.all.accept_ra=0 
net.ipv6.conf.default.accept_ra=0"
 l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf 
/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf 
/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ 
{print $2}' /etc/default/ufw)"
 KPF()
 { 
 # comment out incorrect parameter(s) in kernel parameter file(s)
 l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv --
"\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
 for l_bkpf in $l_fafile; do
 echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
 sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
 done
 # Set correct parameter in a kernel parameter file
 if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" 
$l_searchloc; then
 echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in 
\"$l_kpfile\""
 echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
 fi
 # Set correct parameter in active kernel parameters
 l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
 if [ "$l_krp" != "$l_kpvalue" ]; then
 echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active 
kernel parameters"
 sysctl -w "$l_kpname=$l_kpvalue"
 sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< 
"$l_kpname")"
 fi
 }
 IPV6F_CHK()
 {
 l_ipv6s=""
 grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -
o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} 
\;)
 if [ -s "$grubfile" ]; then
 ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq 
-- ipv6.disable=1 && l_ipv6s="disabled"
 fi
 if grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
 grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc 
&& \
 sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
 sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
 l_ipv6s="disabled"
 fi
 if [ -n "$l_ipv6s" ]; then
 echo -e "\n - IPv6 is disabled on the system, \"$l_kpname\" is not 
applicable"
 else
 KPF
 fi
 }
 for l_kpe in $l_parlist; do
 l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")" 
 l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")" 
 if grep -q '^net.ipv6.' <<< "$l_kpe"; then
 l_kpfile="/etc/sysctl.d/60-netipv6_sysctl.conf"
 IPV6F_CHK
 else
 l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
 KPF
 fi
 done
}

#########################################
#3.5 Firewall Configuration###############     
#3.5.1 Configure UncomplicatedFirewall####    
#3.5.1.1 Ensure ufw is installed (Automated)    
#3.5.1.2 Ensure iptables-persistent is not installed with ufw (Automated)   
#3.5.1.3 Ensure ufw service is enabled (Automated)      
#3.5.1.4 Ensure ufw loopback traffic is configured (Automated)   
#3.5.1.5 Ensure ufw outbound connections are configured (Manual)  
#3.5.1.6 Ensure ufw firewall rules exist for all open ports (Automated)    
#3.5.1.7 Ensure ufw default deny firewall policy (Automated)

apt install ufw

apt purge iptables-persistent

systemctl unmask ufw.service
systemctl --now enable ufw.service
active
ufw enable

ufw allow in on lo
ufw allow out on lo
ufw deny in from 127.0.0.0/8
ufw deny in from ::1

ufw allow out on all

ufw allow in <port>/<tcp or udp protocol>

ufw default deny incoming
ufw default deny outgoing
ufw default deny routed

#########################################
#3.5.2 Configure nftables.################      
#3.5.2.1 Ensure nftables is installed (Automated)   
#3.5.2.2 Ensure ufw is uninstalled or disabled with nftables (Automated) 
#3.5.2.3 Ensure iptables are flushed with nftables (Manual)   
#3.5.2.4 Ensure a nftables table exists (Automated)  
#3.5.2.5 Ensure nftables base chains exist (Automated)  
#3.5.2.6 Ensure nftables loopback traffic is configured (Automated) 
#3.5.2.7 Ensure nftables outbound and established connections are configured (Manual) 
#3.5.2.8 Ensure nftables default deny firewall policy (Automated)    
#3.5.2.9 Ensure nftables service is enabled (Automated)  
#3.5.2.10 Ensure nftables rules are permanent (Automated)

apt install nftables

apt purge ufw
ufw disable

iptables -F
ip6tables -F

nft create table inet filter

nft create chain inet filter input { type filter hook input priority 0 \; }
nft create chain inet filter forward { type filter hook forward priority 0 \; }
nft create chain inet filter output { type filter hook output priority 0 \; }

nft add rule inet filter input iif lo accept
nft create rule inet filter input ip saddr 127.0.0.0/8 counter drop
nft add rule inet filter input ip6 saddr ::1 counter drop

nft add rule inet filter input ip protocol tcp ct state established accept
nft add rule inet filter input ip protocol udp ct state established accept
nft add rule inet filter input ip protocol icmp ct state established accept
nft add rule inet filter output ip protocol tcp ct state new,related,established accept
nft add rule inet filter output ip protocol udp ct state new,related,established accept
nft add rule inet filter output ip protocol icmp ct state new,related,established accept

nft chain <table family> <table name> <chain name> { policy drop \; }
nft chain inet filter input { policy drop \; }
nft chain inet filter forward { policy drop \; }
nft chain inet filter output { policy drop \; }

systemctl enable nftables


#########################################
#3.5.3 Configure iptables#################      
#3.5.3.1 Configure iptables software ##### 
#3.5.3.1.1 Ensure iptables packages are installed (Automated)  
#3.5.3.1.2 Ensure nftables is not installed with iptables (Automated)  
#3.5.3.1.3 Ensure ufw is uninstalled or disabled with iptables (Automated)

apt install iptables iptables-persistent

apt purge nftables

apt purge ufw


#########################################
#3.5.3.2 Configure IPv4 iptables##########  
#3.5.3.2.1 Ensure iptables default deny firewall policy (Automated)    
#3.5.3.2.2 Ensure iptables loopback traffic is configured (Automated)    
#3.5.3.2.3 Ensure iptables outbound and established connections are configured (Manual)

#!/bin/bash
# Flush IPtables rules
iptables -F
# Ensure default deny firewall policy
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
# Ensure loopback traffic is configured
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
# Ensure outbound and established connections are configured
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
# Open inbound ssh(tcp port 22) connections
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP

iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

iptables -A INPUT -p <protocol> --dport <port> -m state --state NEW -j 
ACCEPT


#########################################
#3.5.3.3 Configure IPv6 ip6tables#########  
#3.5.3.3.1 Ensure ip6tables default deny firewall policy (Automated)  
#3.5.3.3.2 Ensure ip6tables loopback traffic is configured (Automated) 
#3.5.3.3.3 Ensure ip6tables outbound and established connections are configured (Manual) 
#3.5.3.3.4 Ensure ip6tables firewall rules exist for all open ports (Automated)

#!/bin/bash
# Flush ip6tables rules
ip6tables -F
# Ensure default deny firewall policy
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
# Ensure loopback traffic is configured
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT -s ::1 -j DROP
# Ensure outbound and established connections are configured
ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
# Open inbound ssh(tcp port 22) connections
ip6tables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP

ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT -s ::1 -j DROP

ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

# ip6tables -A INPUT -p <protocol> --dport <port> -m state --state NEW -j 
ACCEPT




#########################################
#4 Logging and Auditing###################      
#4.1 Configure System Accounting (auditd)###########   
#4.1.1 Ensure auditing is enabled###################    
#4.1.1.1 Ensure auditd is installed (Automated)    
#4.1.1.2 Ensure auditd service is enabled and active (Automated) 
#4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled (Automated)  
#4.1.1.4 Ensure audit_backlog_limit is sufficient (Automated)

apt install auditd audispd-plugins
systemctl --now enable auditd

add_string 'GRUB_CMDLINE_LINUX="' "audit=1 " "/etc/default/grub"
update-grub

set_directive "max_log_file " "1024" "/etc/audit/auditd.conf"

#########################################
#4.1.2 Configure Data Retention###########   
#4.1.2.1 Ensure audit log storage size is configured (Automated)   
#4.1.2.2 Ensure audit logs are not automatically deleted (Automated)
#4.1.2.3 Ensure system is disabled when audit logs are full (Automated) 

set_directive "max_log_file " "1024" "/etc/audit/auditd.conf"

set_directive "max_log_file_action " "keep_logs" "/etc/audit/auditd.conf"

set_directive "space_left_action " "email" "/etc/audit/auditd.conf"
set_directive "action_mail_acct " "root" "/etc/audit/auditd.conf"
set_directive "admin_space_left_action " "halt" "/etc/audit/auditd.conf"

##########################################
#4.1.4 Configure auditd file access #######   
#4.1.4.1 Ensure audit log files are mode 0640 or less permissive (Automated)   
#4.1.4.2 Ensure only authorized users own audit log files (Automated)  
#4.1.4.3 Ensure only authorized groups are assigned ownership of audit log files (Automated)   
#4.1.4.4 Ensure the audit log directory is 0750 or more restrictive (Automated)  
#4.1.4.5 Ensure audit configuration files are 640 or more restrictive (Automated) 
#4.1.4.6 Ensure audit configuration files are owned by root (Automated) 
#4.1.4.7 Ensure audit configuration files belong to group root (Automated)   
#4.1.4.8 Ensure audit tools are 755 or more restrictive (Automated)    
#4.1.4.9 Ensure audit tools are owned by root (Automated)    
#4.1.4.10 Ensure audit tools belong to group root (Automated) 
#4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools (Automated)

[ -f /etc/audit/auditd.conf ] && find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f \( ! -perm 600 -a ! -perm 0400 -a ! -perm 0200 -a ! -perm 0000 -a ! -perm 0640 -a ! -perm 0440 -a ! -perm 0040 \) -exec chmod u-x,g-wx,o-rwx {} +

[ -f /etc/audit/auditd.conf ] && find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f ! -user root -exec chown root {} +

find $(dirname $(awk -F"=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs)) -type f \( ! -group adm -a ! -group root \) -exec chgrp adm {} +
chgrp adm /var/log/audit/
sed -ri 's/^\s*#?\s*log_group\s*=\s*\S+(\s*#.*)?.*$/log_group = adm\1/'/etc/audit/auditd.conf
systemctl restart auditd

chmod g-w,o-rwx "$(dirname $(awk -F"=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf))"

find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec chmod u-x,g-wx,o-rwx {} +

find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec chown root {} +

find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} +

chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

chown root:root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

###########################################
#4.2 Configure Logging######################      
#4.2.1 Configure journald ##################     
#4.2.1.1 Ensure journald is configured to send logs to a remote log host##########     
#4.2.1.1.1 Ensure systemd-journal-remote is installed (Automated)    
#4.2.1.1.2 Ensure systemd-journal-remote is configured (Manual)      
#4.2.1.1.3 Ensure systemd-journal-remote is enabled (Manual)  
#4.2.1.1.4 Ensure journald is not configured to recieve logs from a remote client (Automated)     
#4.2.1.2 Ensure journald service is enabled (Automated)    
#4.2.1.3 Ensure journald is configured to compress large log files (Automated)       
#4.2.1.4 Ensure journald is configured to write logfiles to persistent disk (Automated)     
#4.2.1.5 Ensure journald is not configured to send logs to rsyslog (Manual)  
#4.2.1.6 Ensure journald log rotation is configured per site policy (Manual)    
#4.2.1.7 Ensure journald default file permissions configured (Manual)

apt install systemd-journal-remote

systemctl --now enable systemd-journal-upload.service

systemctl --now disable systemd-journal-remote.socket



add_string '$FileCreateMode ' "0640" "/etc/rsyslog.conf"



systemctl restart systemd-journald

systemctl restart systemd-journald

systemctl restart systemd-journald



###########################################
#4.2.2 Configure rsyslog####################        
#4.2.2.1 Ensure rsyslog is installed (Automated)   
#4.2.2.2 Ensure rsyslog service is enabled (Automated)    
#4.2.2.3 Ensure journald is configured to send logs to rsyslog (Manual)      
#4.2.2.4 Ensure rsyslog default file permissions are configured (Automated)   
#4.2.2.5 Ensure logging is configured (Manual)       595
#4.2.2.6 Ensure rsyslog is configured to send logs to a remote log host (Manual)      
#4.2.2.7 Ensure rsyslog is not configured to receive logs from a remote client (Automated) 
#4.2.3 Ensure all logfiles have appropriate permissions and ownership (Automated)

apt install rsyslog

systemctl --now enable rsyslog

systemctl restart rsyslog

#!/usr/bin/env bash
{
 echo -e "\n- Start remediation - logfiles have appropriate permissions and 
ownership"
 find /var/log -type f | while read -r fname; do
 bname="$(basename "$fname")"
 case "$bname" in
 lastlog | lastlog.* | wtmp | wtmp.* | btmp | btmp.*)
 ! stat -Lc "%a" "$fname" | grep -Pq --
'^\h*[0,2,4,6][0,2,4,6][0,4]\h*$' && echo -e "- changing mode on \"$fname\"" 
&& chmod ug-x,o-wx "$fname"
 ! stat -Lc "%U" "$fname" | grep -Pq -- '^\h*root\h*$' && echo -e 
"- changing owner on \"$fname\"" && chown root "$fname"
 ! stat -Lc "%G" "$fname" | grep -Pq -- '^\h*(utmp|root)\h*$' && 
echo -e "- changing group on \"$fname\"" && chgrp root "$fname"
 ;;
 secure | auth.log)
 ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,4]0\h*$' 
&& echo -e "- changing mode on \"$fname\"" && chmod u-x,g-wx,o-rwx "$fname"
 ! stat -Lc "%U" "$fname" | grep -Pq -- '^\h*(syslog|root)\h*$' && 
echo -e "- changing owner on \"$fname\"" && chown root "$fname"
 ! stat -Lc "%G" "$fname" | grep -Pq -- '^\h*(adm|root)\h*$' && 
echo -e "- changing group on \"$fname\"" && chgrp root "$fname"
 ;;
 SSSD | sssd)
 ! stat -Lc "%a" "$fname" | grep -Pq --
'^\h*[0,2,4,6][0,2,4,6]0\h*$' && echo -e "- changing mode on \"$fname\"" && 
chmod ug-x,o-rwx "$fname"
 ! stat -Lc "%U" "$fname" | grep -Piq -- '^\h*(SSSD|root)\h*$' && 
echo -e "- changing owner on \"$fname\"" && chown root "$fname"
 ! stat -Lc "%G" "$fname" | grep -Piq -- '^\h*(SSSD|root)\h*$' && 
echo -e "- changing group on \"$fname\"" && chgrp root "$fname"
 ;;
 gdm | gdm3)
 ! stat -Lc "%a" "$fname" | grep -Pq --
'^\h*[0,2,4,6][0,2,4,6]0\h*$' && echo -e "- changing mode on \"$fname\"" && 
chmod ug-x,o-rwx
 ! stat -Lc "%U" "$fname" | grep -Pq -- '^\h*root\h*$' && echo -e 
"- changing owner on \"$fname\"" && chown root "$fname"
 ! stat -Lc "%G" "$fname" | grep -Pq -- '^\h*(gdm3?|root)\h*$' && 
echo -e "- changing group on \"$fname\"" && chgrp root "$fname"
 ;;
 *.journal)
 ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,4]0\h*$' 
&& echo -e "- changing mode on \"$fname\"" && chmod u-x,g-wx,o-rwx "$fname"
 ! stat -Lc "%U" "$fname" | grep -Pq -- '^\h*root\h*$' && echo -e 
"- changing owner on \"$fname\"" && chown root "$fname"
 ! stat -Lc "%G" "$fname" | grep -Pq -- '^\h*(systemdjournal|root)\h*$' && echo -e "- changing group on \"$fname\"" && chgrp root 
"$fname"
 ;;
 *)
 ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,4]0\h*$' 
&& echo -e "- changing mode on \"$fname\"" && chmod u-x,g-wx,o-rwx "$fname"
 ! stat -Lc "%U" "$fname" | grep -Pq -- '^\h*(syslog|root)\h*$' && 
echo -e "- changing owner on \"$fname\"" && chown root "$fname"
Page 607
 ! stat -Lc "%G" "$fname" | grep -Pq -- '^\h*(adm|root)\h*$' && 
echo -e "- changing group on \"$fname\"" && chgrp root "$fname"
 ;;
 esac
 done
 echo -e "- End remediation - logfiles have appropriate permissions and 
ownership\n"
}


    
###########################################
#5 Access, Authentication and Authorization#    
#5.1 Configure time-based job schedulers ###   
#5.1.1 Ensure cron daemon is enabled and running (Automated)   
#5.1.2 Ensure permissions on /etc/crontab are configured (Automated)
#5.1.3 Ensure permissions on /etc/cron.hourly are configured (Automated) 
#5.1.4 Ensure permissions on /etc/cron.daily are configured (Automated) 
#5.1.5 Ensure permissions on /etc/cron.weekly are configured (Automated) 
#5.1.6 Ensure permissions on /etc/cron.monthly are configured (Automated)
#5.1.7 Ensure permissions on /etc/cron.d are configured (Automated)  
#5.1.8 Ensure cron is restricted to authorized users (Automated)  
#5.1.9 Ensure at is restricted to authorized users (Automated) 

systemctl --now enable cron

chown root:root /etc/crontab
chmod og-rwx /etc/crontab

chown root:root /etc/cron.hourly/
chmod og-rwx /etc/cron.hourly/

chown root:root /etc/cron.daily/
chmod og-rwx /etc/cron.daily/

chown root:root /etc/cron.weekly/
chmod og-rwx /etc/cron.weekly/

chown root:root /etc/cron.monthly/
chmod og-rwx /etc/cron.monthly/

chown root:root /etc/cron.d/
chmod og-rwx /etc/cron.d/

rm /etc/cron.deny
touch /etc/cron.allow
chmod g-wx,o-rwx /etc/cron.allow
chown root:root /etc/cron.allow

rm /etc/at.deny
touch /etc/at.allow
chmod g-wx,o-rwx /etc/at.allow
chown root:root /etc/at.allow

########################################### 
#5.2 Configure SSH Server ##################   
#5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Automated)   
#5.2.2 Ensure permissions on SSH private host key files are configured (Automated)     
#5.2.3 Ensure permissions on SSH public host key files are configured (Automated) 
#5.2.5 Ensure SSH LogLevel is appropriate (Automated) 
#5.2.6 Ensure SSH PAM is enabled (Automated)
#5.2.7 Ensure SSH root login is disabled (Automated)  
#5.2.8 Ensure SSH HostbasedAuthentication is disabled (Automated)  
#5.2.9 Ensure SSH PermitEmptyPasswords is disabled (Automated)  
#5.2.10 Ensure SSH PermitUserEnvironment is disabled (Automated)  
#5.2.11 Ensure SSH IgnoreRhosts is enabled (Automated)  
#5.2.12 Ensure SSH X11 forwarding is disabled (Automated) 
#5.2.13 Ensure only strong Ciphers are used (Automated)  
#5.2.14 Ensure only strong MAC algorithms are used (Automated)    
#5.2.15 Ensure only strong Key Exchange algorithms are used (Automated) 
#5.2.16 Ensure SSH AllowTcpForwarding is disabled (Automated)  
#5.2.17 Ensure SSH warning banner is configured (Automated)
#5.2.18 Ensure SSH MaxAuthTries is set to 4 or less (Automated)  
#5.2.19 Ensure SSH MaxStartups is configured (Automated) 
#5.2.20 Ensure SSH MaxSessions is set to 10 or less (Automated) 
#5.2.21 Ensure SSH LoginGraceTime is set to one minute or less (Automated) 
#5.2.22 Ensure SSH Idle Timeout Interval is configured (Automated)

chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

#!/usr/bin/env bash
{
 l_skgn="ssh_keys" # Group designated to own openSSH keys
 l_skgid="$(awk -F: '($1 == "'"$l_skgn"'"){print $3}' /etc/group)"
 awk '{print}' <<< "$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -
exec stat -L -c "%n %#a %U %G %g" {} +)" | (while read -r l_file l_mode 
l_owner l_group l_gid; do
 [ -n "$l_skgid" ] && l_cga="$l_skgn" || l_cga="root"
 [ "$l_gid" = "$l_skgid" ] && l_pmask="0137" || l_pmask="0177"
 l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"
 if [ $(( $l_mode & $l_pmask )) -gt 0 ]; then
 echo -e " - File: \"$l_file\" is mode \"$l_mode\" changing to mode: 
\"$l_maxperm\""
 if [ -n "$l_skgid" ]; then
 chmod u-x,g-wx,o-rwx "$l_file"
 else
 chmod u-x,go-rwx "$l_file"
 fi
 fi
 if [ "$l_owner" != "root" ]; then
 echo -e " - File: \"$l_file\" is owned by: \"$l_owner\" changing 
owner to \"root\""
 chown root "$l_file"
 fi
 if [ "$l_group" != "root" ] && [ "$l_gid" != "$l_skgid" ]; then
 echo -e " - File: \"$l_file\" is owned by group \"$l_group\" should 
belong to group \"$l_cga\""
 chgrp "$l_cga" "$l_file"
 fi
 done
 )
}

find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,gowx {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;

############################################
#5.3 Configure privilege escalation##########   
#5.3.1 Ensure sudo is installed (Automated)     
#5.3.2 Ensure sudo commands use pty (Automated)
#5.3.3 Ensure sudo log file exists (Automated)   
#5.3.4 Ensure users must provide password for privilege escalation (Automated)  
#5.3.5 Ensure re-authentication for privilege escalation is not disabled globally (Automated)
#5.3.6 Ensure sudo authentication timeout is configured correctly (Automated)
#5.3.7 Ensure access to the su command is restricted (Automated)

apt install sudo

############################################ 
#5.4 Configure PAM ##########################    
#5.4.1 Ensure password creation requirements are configured (Automated)  
#5.4.2 Ensure lockout for failed password attempts is configured (Automated)
#5.4.3 Ensure password reuse is limited (Automated)
#5.4.4 Ensure password hashing algorithm is up to date with the latest standards (Automated)
#5.4.5 Ensure all current passwords uses the configured hashing algorithm (Manual) 

apt install libpam-pwquality


############################################ 
#5.5 User Accounts and Environment########### 
#5.5.1 Set Shadow Password Suite Parameters ##
#5.5.1.1 Ensure minimum days between password changes is configured (Automated) 
#5.5.1.2 Ensure password expiration is 365 days or less (Automated) 
#5.5.1.3 Ensure password expiration warning days is 7 or more (Automated) 
#5.5.1.4 Ensure inactive password lock is 30 days or less (Automated)
#5.5.1.5 Ensure all users last password change date is in the past (Automated)    
#5.5.2 Ensure system accounts are secured (Automated)  
#5.5.3 Ensure default group for the root account is GID 0 (Automated)   
#5.5.4 Ensure default user umask is 027 or more restrictive (Automated)  
#5.5.5 Ensure default user shell timeout is 900 seconds or less (Automated)

############################################
#6 System Maintenance######################## 
#6.1 System File Permissions#################   
#6.1.1 Ensure permissions on /etc/passwd are configured (Automated)     
#6.1.2 Ensure permissions on /etc/passwd- are configured (Automated)      
#6.1.3 Ensure permissions on /etc/group are configured (Automated)   
#6.1.4 Ensure permissions on /etc/group- are configured (Automated)   
#6.1.5 Ensure permissions on /etc/shadow are configured (Automated)    
#6.1.6 Ensure permissions on /etc/shadow- are configured (Automated)    
#6.1.7 Ensure permissions on /etc/gshadow are configured (Automated)    
#6.1.8 Ensure permissions on /etc/gshadow- are configured (Automated)   
#6.1.9 Ensure no world writable files exist (Automated)  
#6.1.10 Ensure no unowned files or directories exist (Automated)  
#6.1.11 Ensure no ungrouped files or directories exist (Automated)     
#6.1.12 Audit SUID executables (Manual)     
#6.1.13 Audit SGID executables (Manual)

chmod u-x,go-wx /etc/passwd
chown root:root /etc/passwd

chmod u-x,go-wx /etc/passwd-
chown root:root /etc/passwd-

chmod u-x,go-wx /etc/group
chown root:root /etc/group

chmod u-x,go-wx /etc/group-
chown root:root /etc/group-

chown root:shadow /etc/shadow
chmod u-x,g-wx,o-rwx /etc/shadow

chown root:shadow /etc/shadow-
chmod u-x,g-wx,o-rwx /etc/shadow

chown root:shadow /etc/gshadow
chmod u-x,g-wx,o-rwx /etc/gshadow

chown root:shadow /etc/gshadow-
chmod u-x,g-wx,o-rwx /etc/gshadow

#############################################
#6.2 Local User and Group Settings ###########    
#6.2.1 Ensure accounts in /etc/passwd use shadowed passwords (Automated)    
#6.2.2 Ensure /etc/shadow password fields are not empty (Automated)      
#6.2.3 Ensure all groups in /etc/passwd exist in /etc/group (Automated)     
#6.2.4 Ensure shadow group is empty (Automated)       
#6.2.5 Ensure no duplicate UIDs exist (Automated)         
#6.2.6 Ensure no duplicate GIDs exist (Automated)       
#6.2.7 Ensure no duplicate user names exist (Automated)       
#6.2.8 Ensure no duplicate group names exist (Automated)       
#6.2.9 Ensure root PATH Integrity (Automated)       
#6.2.10 Ensure root is the only UID 0 account (Automated)   
#6.2.11 Ensure local interactive user home directories exist (Automated)    
#6.2.12 Ensure local interactive users own their home directories (Automated)      
#6.2.13 Ensure local interactive user home directories are mode 750 or more restrictive (Automated)  
#6.2.14 Ensure no local interactive user has .netrc files (Automated)    
#6.2.15 Ensure no local interactive user has .forward files (Automated) 
#6.2.16 Ensure no local interactive user has .rhosts files (Automated)
#6.2.17 Ensure local interactive user dot files are not group or world writable (Automated)

sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd

# passwd -l <username> es opcional, si una cuenta no tiene contraseña

# sed -ri 's/(^shadow:[^:]*:[^:]*:)([^:]+$)/\1/' /etc/group opcional

# usermod -g <primary group> <user> opcional

#Crear un directorio de inicio para un usuario opcional,cuyo directorio no existe
#!/usr/bin/env bash
#{
# valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -
#d '|' - ))$"
# awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' 
#/etc/passwd | while read -r user home; do
# if [ ! -d "$home" ]; then 
# echo -e "\n- User \"$user\" home directory \"$home\" doesn't 
#exist\n- creating home directory \"$home\"\n"
# mkdir "$home"
# chmod g-w,o-wrx "$home"
# chown "$user" "$home"
# fi
# done
#}

#!/usr/bin/env bash
{
 output=""
 valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -
d '|' - ))$"
 awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' 
/etc/passwd | while read -r user home; do
 owner="$(stat -L -c "%U" "$home")"
 if [ "$owner" != "$user" ]; then
 echo -e "\n- User \"$user\" home directory \"$home\" is owned by 
user \"$owner\"\n - changing ownership to \"$user\"\n"
 chown "$user" "$home"
 fi
 done
}

#!/usr/bin/env bash
{
 output=""
 perm_mask='0027'
 maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
 valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -
d '|' - ))$"
 awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' 
/etc/passwd | (while read -r user home; do
 if [ -d "$home" ]; then
 mode=$( stat -L -c '%#a' "$home" )
 [ $(( $mode & $perm_mask )) -gt 0 ] && output="$output\n- User $user 
home directory: \"$home\" is too permissive: \"$mode\" (should be: 
\"$maxperm\" or more restrictive)"
 fi
 done
 if [ -n "$output" ]; then
 echo -e "\n- Failed:$output"
 else
 echo -e "\n- Passed:\n- All user home directories are mode: 
\"$maxperm\" or more restrictive"
 fi
 )
}

#opcional
#!/usr/bin/env bash
#{
# perm_mask='0177'
# valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -
#d '|' - ))$"
# awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' 
#/etc/passwd | while read -r user home; do
# if [ -f "$home/.netrc" ]; then
# echo -e "\n- User \"$user\" file: \"$home/.netrc\" exists\n -
#removing file: \"$home/.netrc\"\n"
# rm -f "$home/.netrc"
# fi
# done
#}

#opcional
#!/usr/bin/env bash
#{
# output=""
# fname=".forward"
# valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -
#d '|' - ))$"
# awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' 
#/etc/passwd | (while read -r user home; do
# if [ -f "$home/$fname" ]; then
# echo -e "$output\n- User \"$user\" file: \"$home/$fname\" exists\n 
#- removing file: \"$home/$fname\"\n"
# rm -r "$home/$fname"
# fi
# done
# )
#}


#opcional
#!/usr/bin/env bash
#{
# perm_mask='0022'
# valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -
#d '|' - ))$"
# awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }'
#/etc/passwd | while read -r user home; do
# find "$home" -type f -name '.*' | while read -r dfile; do
# mode=$( stat -L -c '%#a' "$dfile" )
# if [ $(( $mode & $perm_mask )) -gt 0 ]; then
# echo -e "\n- Modifying User \"$user\" file: \"$dfile\"\nremoving group and other write permissions"
# chmod go-w "$dfile"
# fi
# done
# done
#}


