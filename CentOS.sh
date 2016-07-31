#!/bin/bash
#CentOS 7 Audit Script
#Developed and Modified By Shravan Kumar for the official purpose only
#This configuration review script is developed according specific needs.
#Last Update Data : 26 July, 2016
# Use following command to run this scipt 
# chmod +x CentOS_audit.sh
# ./CentOS_audit.sh



echo "SecureLayer7 CentOS Audit Started" 
echo "==================================================================================" 
echo ">>>>> 1 Install Updates, Patches and Additional Security Software  <<<<< "
echo "    *************** 1.1 Filesystem Configuration *****************"
echo "1.1.1 Create Separate Partition for /tmp" 
grep "[[:space:]]/tmp[[:space:]]" /etc/fstab 


echo "=================================================================================="  
echo "1.1.2 Set nodev option for /tmp Partition" 
grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep nodev 
mount | grep "[[:space:]]/tmp[[:space:]]" | grep nodev 


echo "=================================================================================="  
echo "1.1.3 Set nosuid option for /tmp Partition" 
grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep nosuid 
mount | grep "[[:space:]]/tmp[[:space:]]" | grep nosuid 


echo "=================================================================================="  
echo "1.1.4 Set noexec option for /tmp Partition" 
grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep noexec 
mount | grep "[[:space:]]/tmp[[:space:]]" | grep noexec 


echo "=================================================================================="  
echo "1.1.5 Create Separate Partition for /var" 
grep "[[:space:]]/var[[:space:]]" /etc/fstab 


echo "=================================================================================="  
echo "1.1.6 Bind Mount the /var/tmp directory to /tmp" 
grep -e "^/tmp[[:space:]]" /etc/fstab | grep /var/tmp  
mount | grep -e "^/tmp[[:space:]]" | grep /var/tmp     


echo "=================================================================================="  
echo "1.1.7 Create Separate Partition for /var/log" 
grep "[[:space:]]/var/log[[:space:]]" /etc/fstab    

echo "=================================================================================="  
echo "1.1.8 Create Separate Partition for /var/log/audit"  
grep "[[:space:]]/var/log/audit[[:space:]]" /etc/fstab     


echo "=================================================================================="  
echo "1.1.9 Create Separate Partition for /home"   
grep "[[:space:]]/home[[:space:]]" /etc/fstab  



echo "=================================================================================="  
echo "1.1.10 Add nodev Option to /home" 
grep "[[:space:]]/home[[:space:]]" /etc/fstab 
mount | grep /home  

echo "=================================================================================="
echo "1.1.11 Add nodev Option to Removable Media Partitions"
echo "grep <each removable media mountpoint> /etc/fstab"
echo "work on it "


echo "=================================================================================="
echo "1.1.12 Add noexec Option to Removable Media Partitions"
echo "grep <each removable media mountpoint> /etc/fstab"
echo "work on it "

echo "=================================================================================="
echo "1.1.13 Add nosuid Option to Removable Media Partitions"
echo "grep <each removable media mountpoint> /etc/fstab"
echo "work on it "


echo "=================================================================================="
echo "1.1.14 Add nodev Option to /dev/shm Partition"
grep /dev/shm /etc/fstab | grep nodev
mount | grep /dev/shm | grep nodev

echo "=================================================================================="
echo "1.1.15 Add nosuid Option to /dev/shm Partition"
grep /dev/shm /etc/fstab | grep nosuid
mount | grep /dev/shm | grep nosuid

echo "=================================================================================="
echo "1.1.16 Add noexec Option to /dev/shm Partition"
grep /dev/shm /etc/fstab | grep noexec
mount | grep /dev/shm | grep noexec

echo "=================================================================================="
echo "1.1.17 Set Sticky Bit on All World-Writable Directories"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null

echo "=================================================================================="
echo "1.1.18 Disable Mounting of cramfs Filesystems"
/sbin/modprobe -n -v cramfs
/sbin/lsmod | grep cramfs


echo "=================================================================================="
echo "1.1.19 Disable Mounting of freevxfs Filesystems"
/sbin/modprobe -n -v freevxfs
/sbin/lsmod | grep freevxfs


echo "=================================================================================="
echo "1.1.20 Disable Mounting of jffs2 Filesystems"
/sbin/modprobe -n -v jffs2
/sbin/lsmod | grep jffs2


echo "=================================================================================="
echo "1.1.21 Disable Mounting of hfs Filesystems"
/sbin/modprobe -n -v hfs
/sbin/lsmod | grep hfs

echo "=================================================================================="
echo "1.1.22 Disable Mounting of hfsplus Filesystems"
/sbin/modprobe -n -v hfsplus
/sbin/lsmod | grep hfsplus

echo "=================================================================================="
echo "1.1.23 Disable Mounting of squashfs Filesystems"
/sbin/modprobe -n -v squashfs
/sbin/lsmod | grep squashfs

echo "=================================================================================="
echo "1.1.24 Disable Mounting of udf Filesystems"
/sbin/modprobe -n -v udf
/sbin/lsmod | grep udf


echo "=================================================================================="
echo "    *************** 1.2 Configure Software Updates *****************"
echo "1.2.1 Verify CentOS GPG Key is Installed"
rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey


echo "=================================================================================="
echo "1.2.2 Verify that gpgcheck is Globally Activated"
grep gpgcheck /etc/yum.conf

echo "=================================================================================="
echo "1.2.3 Obtain Software Package Updates with yum"
yum check-update

echo "=================================================================================="
echo "1.2.4 Verify Package Integrity Using RPM"
rpm -qVa | awk '$2 != "c" { print $0}'



echo "=================================================================================="
echo "    *************** 1.3 Advanced Intrusion Detection Environment *****************"
echo "1.3.1 Install AIDE"
rpm -q aide


echo "=================================================================================="
echo "1.3.2 Implement Periodic Execution of File Integrity"
crontab -u root -l | grep aide


echo "=================================================================================="
echo "    *************** 1.4 Configure SELinux *****************"
echo "1.4.1 Ensure SELinux is not disabled in /boot/grub2/grub.cfg"
grep selinux=0 /boot/grub2/grub.cfg
grep enforcing=0 /boot/grub2/grub.cfg



echo "=================================================================================="
echo "1.4.2 Set the SELinux State"
grep SELINUX=enforcing /etc/selinux/config
/usr/sbin/sestatus

echo "=================================================================================="
echo "1.4.3 Set the SELinux Policy"
grep SELINUXTYPE=targeted /etc/selinux/config
/usr/sbin/sestatus

echo "=================================================================================="
echo "1.4.4 Remove SETroubleshoot"
rpm -q setroubleshoot



echo "=================================================================================="
echo "1.4.5 Remove MCS Translation Service (mcstrans)"
rpm -q mcstrans


echo "=================================================================================="
echo "1.4.6 Check for Unconfined Daemons"
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{print $NF }'



echo "=================================================================================="
echo "    *************** 1.5 Secure Boot Settings *****************"

echo "1.5.1 Set User/Group Owner on /boot/grub2/grub.cfg"
stat -L -c "%u %g" /boot/grub2/grub.cfg | egrep "0 0"

echo "=================================================================================="
echo "1.5.2 Set Permissions on /boot/grub2/grub.cfg"
stat -L -c "%a" /boot/grub2/grub.cfg | egrep ".00"


echo "=================================================================================="
echo "1.5.3 Set Boot Loader Password"
grep "^set superusers" /boot/grub2/grub.cfg
grep "^password" /boot/grub2/grub.cfg


echo "=================================================================================="
echo "    *************** 1.6 Additional Process Hardening *****************"

echo "1.6.1 Restrict Core Dumps"
grep "hard core" /etc/security/limits.conf
/sbin/sysctl fs.suid_dumpable



echo "=================================================================================="
echo "1.6.2 Enable Randomized Virtual Memory Region Placement"
/sbin/sysctl kernel.randomize_va_space


echo "=================================================================================="
echo "    *************** 1.7 Use the Latest OS Release *****************"
uname -r
cat /etc/centos-release


echo "=================================================================================="
echo ">>>>> 2 OS Services <<<<< "
echo "    *************** 2.1 Remove Legacy Services *****************"

echo "2.1.1 Remove telnet-server"
rpm -q telnet-server

echo "=================================================================================="

echo "2.1.2 Remove telnet Clients"
rpm -q telnet

echo "=================================================================================="
echo "2.1.3 Remove rsh-server"
rpm -q rsh-server

echo "=================================================================================="
echo "2.1.4 Remove rsh"
rpm -q rsh

echo "=================================================================================="
echo "2.1.5 Remove NIS Client"
rpm -q ypbind

echo "=================================================================================="
echo "2.1.6 Remove NIS Server"
rpm -q ypserv

echo "=================================================================================="
echo "2.1.7 Remove tftp"
rpm -q tftp

echo "=================================================================================="
echo "2.1.8 Remove tftp-server"
rpm -q tftp-server

echo "=================================================================================="
echo "2.1.9 Remove talk"
rpm -q talk

echo "=================================================================================="
echo "2.1.10 Remove talk-server"
rpm -q talk-server

echo "=================================================================================="
echo "2.1.11 Remove xinetd"
rpm -q xinetd

echo "=================================================================================="
echo "2.1.12 Disable chargen-dgram"
chkconfig --list chargen-dgram

echo "=================================================================================="
echo "2.1.13 Disable chargen-stream"
chkconfig --list chargen-stream

echo "=================================================================================="
echo "2.1.14 Disable daytime-dgram"
chkconfig --list daytime-dgram

echo "=================================================================================="
echo "2.1.15 Disable daytime-stream"
chkconfig --list daytime-stream

echo "=================================================================================="
echo "2.1.16 Disable echo-dgram"
chkconfig --list echo-stream

echo "=================================================================================="
echo "2.1.18 Disable tcpmux-server"
chkconfig --list tcpmux-server

echo "=================================================================================="
echo ">>>>> 3 Special Purpose Services <<<<< "


echo "3.1 Set Daemon umask"
grep umask /etc/sysconfig/init

echo "=================================================================================="
echo "3.2 Remove the X Window System"
ls -l /etc/systemd/system/default.target | grep graphical.target
rpm -q xorg-x11-server-common

echo "=================================================================================="
echo "3.3 Disable Avahi Server"
systemctl is-enabled avahi-daemon

echo "=================================================================================="
echo "3.4 Disable Print Server - CUPS"
systemctl is-enabled cups

echo "=================================================================================="
echo "3.5 Remove DHCP Server"
rpm -q dhcp


echo "=================================================================================="
echo "3.6 Configure Network Time Protocol (NTP)"
grep "restrict default" /etc/ntp.conf
grep "restrict -6 default" /etc/ntp.conf
grep "^server" /etc/ntp.conf
grep "ntp:ntp" /etc/sysconfig/ntpd


echo "=================================================================================="
echo "3.7 Remove LDAP"
rpm -q openldap-servers
rpm -q openldap-clients


echo "=================================================================================="
echo "3.8 Disable NFS and RPC"
systemctl is-enabled nfslock
systemctl is-enabled rpcgssd
systemctl is-enabled rpcbind
systemctl is-enabled rpcidmapd
systemctl is-enabled rpcsvcgssd

echo "=================================================================================="
echo "3.9 Remove DNS Server"
rpm -q bind

echo "=================================================================================="
echo "3.10 Remove FTP Server"
rpm -q vsftpd


echo "=================================================================================="
echo "3.11 Remove HTTP Server"
rpm -q httpd


echo "=================================================================================="
echo "3.12 Remove Dovecot"
rpm -q dovecot


echo "=================================================================================="
echo "3.13 Remove Samba"
rpm -q samba

echo "=================================================================================="
echo "3.14 Remove HTTP Proxy Server"
rpm -q squid

echo "=================================================================================="
echo "3.15 Remove SNMP Server"
rpm -q net-snmp

echo "=================================================================================="
echo "3.16 Configure Mail Transfer Agent for Local-Only Mode"
netstat -an | grep LIST | grep ":25[[:space:]]"


echo "=================================================================================="
echo ">>>>> 4 Network Configuration and Firewalls <<<<< "
echo "    *************** 4.1 Modify Network Parameters *****************"

echo "=================================================================================="
echo "4.1.1 Disable IP Forwarding"
/sbin/sysctl net.ipv4.ip_forward

echo "=================================================================================="
echo "4.1.2 Disable Send Packet Redirects"
/sbin/sysctl net.ipv4.conf.all.send_redirects
/sbin/sysctl net.ipv4.conf.default.send_redirects

echo "=================================================================================="

echo "    *************** 4.2 Modify Network Parameters *****************"

echo "4.2.1 Disable Source Routed Packet Acceptance"
/sbin/sysctl net.ipv4.conf.all.accept_source_route
/sbin/sysctl net.ipv4.conf.default.accept_source_route

echo "=================================================================================="

echo "4.2.2 Disable ICMP Redirect Acceptance"
/sbin/sysctl net.ipv4.conf.all.accept_redirects
/sbin/sysctl net.ipv4.conf.default.accept_redirects

echo "=================================================================================="
echo "4.2.3 Disable Secure ICMP Redirect Acceptance"
/sbin/sysctl net.ipv4.conf.all.secure_redirects
/sbin/sysctl net.ipv4.conf.default.secure_redirects

echo "=================================================================================="
echo "4.2.4 Log Suspicious Packets"
/sbin/sysctl net.ipv4.conf.all.log_martians
/sbin/sysctl net.ipv4.conf.default.log_martians

echo "=================================================================================="

echo "4.2.5 Enable Ignore Broadcast Requests"
/sbin/sysctl net.ipv4.icmp_echo_ignore_broadcasts

echo "=================================================================================="
echo "4.2.6 Enable Bad Error Message Protection"
/sbin/sysctl net.ipv4.icmp_ignore_bogus_error_responses

echo "=================================================================================="
echo "4.2.7 Enable RFC-recommended Source Route Validation"
/sbin/sysctl net.ipv4.conf.all.rp_filter
/sbin/sysctl net.ipv4.conf.default.rp_filter

echo "=================================================================================="
echo "4.2.8 Enable TCP SYN Cookies"
/sbin/sysctl net.ipv4.tcp_syncookies

echo "=================================================================================="

echo "    *************** 4.3 Wireless Networking *****************"
echo "4.3.1 Deactivate Wireless Interfaces"
ip link show

echo "=================================================================================="
echo "    *************** 4.4 IPv6 *****************"
echo "---> 4.4.1 Configure IPv6 <---"
echo "4.4.1.1 Disable IPv6 Router Advertisements"
/sbin/sysctl net.ipv6.conf.all.accept_ra
/sbin/sysctl net.ipv6.conf.default.accept_ra

echo "=================================================================================="

echo "4.4.1.2 Disable IPv6 Redirect Acceptance"
/sbin/sysctl net.ipv6.conf.all.accept_redirects
/sbin/sysctl net.ipv6.conf.default.accept_redirects

echo "=================================================================================="
echo "---> 4.4.2 Disable IPv6 <---"
grep net.ipv6.conf.all.disable_ipv6 /etc/sysctl.conf
/sbin/sysctl net.ipv6.conf.all.disable_ipv6

echo "=================================================================================="
echo "    *************** 4.5 Install TCP Wrappers *****************"

echo "4.5.1 Install TCP Wrappers"
yum list tcp_wrappers

echo "=================================================================================="
echo "4.5.2 Create /etc/hosts.allow"
cat /etc/hosts.allow

echo "=================================================================================="
echo "4.5.3 Verify Permissions on /etc/hosts.allow"
/bin/ls -l /etc/hosts.allow

echo "=================================================================================="
echo "4.5.4 Create /etc/hosts.deny"
grep "ALL: ALL" /etc/hosts.deny

echo "=================================================================================="
echo "4.5.5 Verify Permissions on /etc/hosts.deny"
/bin/ls -l /etc/hosts.deny

echo "=================================================================================="

echo "    *************** 4.6 Uncommon Network Protocols *****************"

echo "4.6.1 Disable DCCP"
grep "install dccp /bin/true" /etc/modprobe.d/CIS.conf

echo "=================================================================================="
echo "4.6.2 Disable SCTP"
grep "install sctp /bin/true" /etc/modprobe.d/CIS.conf

echo "=================================================================================="
echo "4.6.3 Disable RDS"
grep "install rds /bin/true" /etc/modprobe.d/CIS.conf

echo "=================================================================================="
echo "4.6.4 Disable TIPC"
grep "install tipc /bin/true" /etc/modprobe.d/CIS.conf

echo "=================================================================================="


echo "    *************** 4.7 Enable firewalld *****************"
systemctl is-enabled firewalld

echo "=================================================================================="
echo ">>>>> 5 Logging and Auditing <<<<< "
echo "    *************** 5.1 Configure rsyslog *****************"

echo "=================================================================================="
echo "5.1.1 Install the rsyslog package"
rpm -q rsyslog

echo "=================================================================================="
echo "5.1.2 Activate the rsyslog Service"
systemctl is-enabled rsyslog

echo "=================================================================================="
echo "5.1.3 Configure /etc/rsyslog.conf"
ls -l /var/log/

echo "=================================================================================="
echo "5.1.4 Create and Set Permissions on rsyslog Log Files"
echo "For each <logfile> listed in the /etc/rsyslog.conf file, perform the following command and verify that the <owner>:<group> is root:root and the permissions are 0600 (for sites that have not implemented a secure group) and root:securegrp with permissions of 0640 \nls -l <logfile>"
echo "Work on it"

echo "=================================================================================="

echo "5.1.5 Configure rsyslog to Send Logs to a Remote Log Host"
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf

echo "=================================================================================="
echo "5.1.6 Accept Remote rsyslog Messages Only on Designated Log Hosts"
grep '$ModLoad imtcp.so' /etc/rsyslog.conf
grep '$InputTCPServerRun' /etc/rsyslog.conf

echo "=================================================================================="


echo "    *************** 5.2 Configure System Accounting *****************"

echo "---> 5.2.1 Configure Data Retention <---"
echo "5.2.1.1 Configure Audit Log Storage Size"
grep max_log_file /etc/audit/auditd.conf

echo "=================================================================================="
echo "5.2.1.2 Disable System on Audit Log Full"
grep space_left_action /etc/audit/auditd.conf
grep action_mail_acct /etc/audit/auditd.conf
grep admin_space_left_action /etc/audit/auditd.conf

echo "=================================================================================="
echo "5.2.1.3 Keep All Auditing Information"
grep max_log_file_action /etc/audit/auditd.conf

echo "=================================================================================="
echo "5.2.2 Enable auditd Service"
systemctl is-enabled auditd

echo "=================================================================================="
echo "5.2.3 Enable Auditing for Processes That Start Prior to auditd"
grep "linux" /boot/grub2/grub.cfg

echo "=================================================================================="
echo "5.2.4 Record Events That Modify Date and Time Information"
grep time-change /etc/audit/audit.rules

echo "=================================================================================="
echo "5.2.5 Record Events That Modify User/Group Information"
grep identity /etc/audit/audit.rules

echo "=================================================================================="
echo "5.2.6 Record Events That Modify the System's Network Environment"
grep system-locale /etc/audit/audit.rules

echo "=================================================================================="
echo "5.2.7 Record Events That Modify the System's Mandatory Access Controls"
grep MAC-policy /etc/audit/audit.rules

echo "=================================================================================="
echo "5.2.8 Collect Login and Logout Events"
grep logins /etc/audit/audit.rules

echo "=================================================================================="
echo "5.2.9 Collect Session Initiation Information"
grep session /etc/audit/audit.rules

echo "=================================================================================="
echo "5.2.10 Collect Discretionary Access Control Permission Modification Events"
grep perm_mod /etc/audit/audit.rules

echo "=================================================================================="
echo "5.2.11 Collect Unsuccessful Unauthorized Access Attempts to Files"
grep access /etc/audit/audit.rules

echo "=================================================================================="
echo "5.2.12 Collect Use of Privileged Commands"
find PART -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }'

echo "=================================================================================="
echo "5.2.13 Collect Successful File System Mounts"
grep mounts /etc/audit/audit.rules

echo "=================================================================================="
echo "5.2.14 Collect File Deletion Events by User"
grep delete /etc/audit/audit.rules

echo "=================================================================================="
echo "5.2.15 Collect Changes to System Administration Scope"
grep scope /etc/audit/audit.rules

echo "=================================================================================="
echo "5.2.16 Collect System Administrator Actions (sudolog)"
grep actions /etc/audit/audit.rules

echo "=================================================================================="
echo "5.2.17 Collect Kernel Module Loading and Unloading"
grep modules /etc/audit/audit.rules

echo "=================================================================================="
echo "5.2.18 Make the Audit Configuration Immutable"
grep "^-e 2" /etc/audit/audit.rules

echo "=================================================================================="
echo "*************** 5.3 Configure logrotate *****************"
grep '{' /etc/logrotate.d/syslog

echo "=================================================================================="

echo ">>>>> 6 System Access, Authentication and Authorization <<<<< "
echo "*************** 6.1 Configure cron and anacron *****************"

echo "6.1.1 Enable anacron Daemon"
rpm -q cronie-anacron

echo "=================================================================================="
echo "6.1.2 Enable crond Daemon"
systemctl is-enabled crond

echo "=================================================================================="
echo "6.1.3 Set User/Group Owner and Permission on /etc/anacrontab"
stat -L -c "%a %u %g" /etc/anacrontab | egrep ".00 0 0"

echo "=================================================================================="
echo "6.1.4 Set User/Group Owner and Permission on /etc/crontab"
stat -L -c "%a %u %g" /etc/crontab | egrep ".00 0 0"

echo "=================================================================================="
echo "6.1.5 Set User/Group Owner and Permission on /etc/cron.hourly"
stat -L -c "%a %u %g" /etc/cron.hourly | egrep ".00 0 0"

echo "=================================================================================="
echo "6.1.6 Set User/Group Owner and Permission on /etc/cron.daily"
stat -L -c "%a %u %g" /etc/cron.daily | egrep ".00 0 0"

echo "=================================================================================="
echo "6.1.7 Set User/Group Owner and Permission on /etc/cron.weekly"
stat -L -c "%a %u %g" /etc/cron.weekly | egrep ".00 0 0"

echo "=================================================================================="
echo "6.1.8 Set User/Group Owner and Permission on /etc/cron.monthly"
stat -L -c "%a %u %g" /etc/cron.monthly | egrep ".00 0 0"

echo "=================================================================================="
echo "6.1.9 Set User/Group Owner and Permission on /etc/cron.d"
stat -L -c "%a %u %g" /etc/cron.d | egrep ".00 0 0"

echo "=================================================================================="
echo "6.1.10 Restrict at Daemon"
stat -L /etc/at.deny > /dev/null
stat -L -c "%a %u %g" /etc/at.allow | egrep ".00 0 0"

echo "=================================================================================="
echo "6.1.11 Restrict at/cron to Authorized Users"
ls -l /etc/cron.deny
ls -l /etc/at.deny
ls -l /etc/cron.allow
ls -l /etc/at.allow

echo "=================================================================================="
echo "*************** 6.2 Configure SSH *****************"
echo "6.2.1 Set SSH Protocol to 2"
grep "^Protocol" /etc/ssh/sshd_config

echo "=================================================================================="
echo "6.2.2 Set LogLevel to INFO"
grep "^LogLevel" /etc/ssh/sshd_config

echo "=================================================================================="
echo "6.2.3 Set Permissions on /etc/ssh/sshd_config"
/bin/ls -l /etc/ssh/sshd_config

echo "=================================================================================="
echo "6.2.4 Disable SSH X11 Forwarding"
grep "^X11Forwarding" /etc/ssh/sshd_config

echo "=================================================================================="
echo "6.2.5 Set SSH MaxAuthTries to 4 or Less"
grep "^MaxAuthTries" /etc/ssh/sshd_config

echo "=================================================================================="
echo "6.2.6 Set SSH IgnoreRhosts to Yes"
grep "^HostbasedAuthentication" /etc/ssh/sshd_config

echo "=================================================================================="
echo "6.2.7 Set SSH HostbasedAuthentication to No"
grep "^HostbasedAuthentication" /etc/ssh/sshd_config

echo "=================================================================================="
echo "6.2.8 Disable SSH Root Login"
grep "^PermitRootLogin" /etc/ssh/sshd_config

echo "=================================================================================="
echo "6.2.9 Set SSH PermitEmptyPasswords to No"
grep "^PermitEmptyPasswords" /etc/ssh/sshd_config

echo "=================================================================================="
echo "6.2.10 Do Not Allow Users to Set Environment Options"
grep PermitUserEnvironment /etc/ssh/sshd_config

echo "=================================================================================="
echo "6.2.11 Use Only Approved Cipher in Counter Mode"
grep "Ciphers" /etc/ssh/sshd_config

echo "=================================================================================="
echo "6.2.12 Set Idle Timeout Interval for User Login"
grep "^ClientAliveInterval" /etc/ssh/sshd_config
grep "^ClientAliveCountMax" /etc/ssh/sshd_config

echo "=================================================================================="
echo "6.2.13 Limit Access via SSH"
grep "^AllowUsers" /etc/ssh/sshd_config
grep "^AllowGroups" /etc/ssh/sshd_config
grep "^DenyUsers" /etc/ssh/sshd_config
grep "^DenyGroups" /etc/ssh/sshd_config

echo "=================================================================================="
echo "6.2.14 Set SSH Banner"
grep "^Banner" /etc/ssh/sshd_config

echo "=================================================================================="
echo "*************** 6.3 Configure PAM *****************"
echo "6.3.1 Upgrade Password Hashing Algorithm to SHA-512"
authconfig --test | grep hashing | grep sha512

echo "=================================================================================="
echo "6.3.2 Set Password Creation Requirement Parameters Using pam_pwquality"
grep pam_pwquality.so /etc/pam.d/system-auth

echo "=================================================================================="
echo "6.3.3 Set Lockout for Failed Password Attempts"
grep "pam_faillock" /etc/pam.d/password-auth
grep "pam_unix.so" /etc/pam.d/password-auth | grep success=1
grep "pam_faillock" /etc/pam.d/system-auth
grep "pam_unix.so" /etc/pam.d/system-auth | grep success=1

echo "=================================================================================="
echo "6.3.4 Limit Password Reuse"
grep "remember" /etc/pam.d/system-auth

echo "=================================================================================="
echo "*************** 6.4 Restrict root Login to System Console *****************"
cat /etc/securetty

echo "=================================================================================="
echo "*************** 6.5 Restrict Access to the su Command *****************"
grep pam_wheel.so /etc/pam.d/su
grep wheel /etc/group

echo "=================================================================================="


echo ">>>>> 7 User Accounts and Environment <<<<< "
echo "*************** 7.1 Set Shadow Password Suite Parameters *****************"



echo "7.1.1 Set Password Expiration Days"
grep PASS_MAX_DAYS /etc/login.defs
echo "work on it chage --list <user>"

echo "=================================================================================="
echo "7.1.2 Set Password Change Minimum Number of Days"
grep PASS_MIN_DAYS /etc/login.defs
echo "work on it chage --list <user> "

echo "=================================================================================="
echo "7.1.3 Set Password Expiring Warning Days"
grep PASS_WARN_AGE /etc/login.defs
echo "work on it chage --list <user>"

echo "=================================================================================="
echo "*************** 7.2 Disable System Accounts *****************"
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin") {print}'

echo "=================================================================================="
echo "*************** 7.3 Set Default Group for root Account *****************"
grep "^root:" /etc/passwd | cut -f4 -d:

echo "=================================================================================="
echo "*************** 7.4 Set Default umask for Users *****************"
grep "^umask 077" /etc/bashrc
grep "^umask 077" /etc/profile.d/*

echo "=================================================================================="
echo "*************** 7.5 Lock Inactive User Accounts *****************"
useradd -D | grep INACTIVE

echo "=================================================================================="
echo ">>>>> 8 Warning Banners <<<<< "


echo "8.1 Set Warning Banner for Standard Login Services"
/bin/ls -l /etc/motd
ls /etc/issue
ls /etc/issue.net

echo "=================================================================================="
echo "8.2 Remove OS Information from Login Warning Banners"
egrep '(\\v|\\r|\\m|\\s)' /etc/issue
egrep '(\\v|\\r|\\m|\\s)' /etc/motd
egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net

echo "=================================================================================="
echo "8.3 Set GNOME Warning Banner"
echo "_______"

echo "=================================================================================="
echo ">>>>> 9 System Maintenance <<<<< "
echo "*************** 9.1 Verify System File Permissions *****************"


echo "9.1.1 Verify System File Permissions"
rpm -V `rpm -qf /etc/passwd`

echo "=================================================================================="
echo "9.1.2 Verify Permissions on /etc/passwd"
/bin/ls -l /etc/passwd

echo "=================================================================================="
echo "9.1.3 Verify Permissions on /etc/shadow"
/bin/ls -l /etc/shadow

echo "=================================================================================="
echo "9.1.4 Verify Permissions on /etc/gshadow"
/bin/ls -l /etc/gshadow

echo "=================================================================================="
echo "9.1.5 Verify Permissions on /etc/group"
/bin/ls -l /etc/group

echo "=================================================================================="
echo "9.1.6 Verify User/Group Ownership on /etc/passwd"
/bin/ls -l /etc/passwd

echo "=================================================================================="
echo "9.1.7 Verify User/Group Ownership on /etc/shadow"
/bin/ls -l /etc/shadow

echo "=================================================================================="
echo "9.1.8 Verify User/Group Ownership on /etc/gshadow"
/bin/ls -l /etc/gshadow

echo "=================================================================================="
echo "9.1.9 Verify User/Group Ownership on /etc/group"
/bin/ls -l /etc/group

echo "=================================================================================="
echo "9.1.10 Find World Writable Files"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002

echo "=================================================================================="
echo "9.1.11 Find Un-owned Files and Directories"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls

echo "=================================================================================="
echo "9.1.12 Find Un-grouped Files and Directories"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls

echo "=================================================================================="
echo "9.1.13 Find SUID System Executables"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print

echo "=================================================================================="
echo "9.1.14 Find SGID System Executables"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print

echo "=================================================================================="
echo "*************** 9.2 Review User and Group Settings *****************"

echo "9.2.1 Ensure Password Fields are Not Empty"
/bin/cat /etc/shadow | /usr/bin/awk -F: '($2 == "" ) { print $1 " does not have a password "}'

echo "=================================================================================="
echo "9.2.2 Verify No Legacy "+" Entries Exist in /etc/passwd File"
/bin/grep '^+:' /etc/passwd

echo "=================================================================================="
echo "9.2.3 Verify No Legacy "+" Entries Exist in /etc/shadow File"
/bin/grep '^+:' /etc/shadow

echo "=================================================================================="
echo "9.2.4 Verify No Legacy "+" Entries Exist in /etc/group File"
/bin/grep '^+:' /etc/group

echo "=================================================================================="
echo "9.2.5 Verify No UID 0 Accounts Exist Other Than root"
/bin/cat /etc/passwd | /usr/bin/awk -F: '($3 == 0) { print $1 }'

echo "=================================================================================="
echo "9.2.6 Ensure root PATH Integrity"
if [ "`echo $PATH | /bin/grep :: `" != "" ]; then
echo "Empty Directory in PATH (::)"
fi
if [ "`echo $PATH | /bin/grep :$`" != "" ]; then
echo "Trailing : in PATH"
fi

p=`echo $PATH | /bin/sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
if [ "$1" = "." ]; then
echo "PATH contains ."
shift
continue
fi
if [ -d $1 ]; then
dirperm=`/bin/ls -ldH $1 | /bin/cut -f1 -d" "`
if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
echo "Group Write permission set on directory $1"
fi
if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
echo "Other Write permission set on directory $1"
fi
dirown=`ls -ldH $1 | awk '{print $3}'`
if [ "$dirown" != "root" ] ; then
echo "$1 is not owned by root"
fi
else
echo "$1 is not a directory"
fi
shift
done

echo "=================================================================================="

echo "9.2.7 Check Permissions on User Home Directories"
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |/bin/awk -F: '($8 == "PS" && $7 != "/sbin/nologin") { print $6 }'`; do
dirperm=`/bin/ls -ld $dir | /bin/cut -f1 -d" "`
if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
echo "Group Write permission set on directory $dir"
fi
if [ `echo $dirperm | /bin/cut -c8 ` != "-" ]; then
echo "Other Read permission set on directory $dir"
fi
if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
echo "Other Write permission set on directory $dir"
fi
if [ `echo $dirperm | /bin/cut -c10 ` != "-" ]; then
echo "Other Execute permission set on directory $dir"
fi
done

echo "=================================================================================="
echo "9.2.8 Check User Dot File Permissions"
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' | 
	/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
		for file in $dir/.[A-Za-z0-9]*; do
			if [ ! -h "$file" -a -f "$file" ]; then 
				fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
				if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]; then 
					echo "Group Write permission set on file $file"
				fi
				if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]; then 
					echo "Other Write permission set on file $file"
				fi 
			fi
		done 
done

echo "=================================================================================="
echo "9.2.9 Check Permissions on User .netrc Files"

for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
for file in $dir/.netrc; do
if [ ! -h "$file" -a -f "$file" ]; then
fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
if [ `echo $fileperm | /bin/cut -c5 ` != "-" ]
then
echo "Group Read set on $file"
fi
if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]
then
echo "Group Write set on $file"
fi
if [ `echo $fileperm | /bin/cut -c7 ` != "-" ]
then
echo "Group Execute set on $file"
fi
if [ `echo $fileperm | /bin/cut -c8 ` != "-" ]
then
echo "Other Read set on $file"
fi
if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]
then
echo "Other Write set on $file"
fi
if [ `echo $fileperm | /bin/cut -c10 ` != "-" ]
then
echo "Other Execute set on $file"
fi
fi
done
done

echo "=================================================================================="
echo "9.2.10 Check for Presence of User .rhosts Files"

for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
for file in $dir/.rhosts; do
if [ ! -h "$file" -a -f "$file" ]; then
echo ".rhosts file in $dir"
fi
done
done




echo "=================================================================================="
echo "9.2.11 Check Groups in /etc/passwd"

for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
grep -q -P "^.*?:x:$i:" /etc/group
if [ $? -ne 0 ]; then
echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
fi
done



echo "=================================================================================="
echo "9.2.12 Check That Users Are Assigned Valid Home Directories"
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
echo "The home directory ($dir) of user $user does not exist."
fi
done

echo "=================================================================================="
echo "9.2.13 Check User Home Directory Ownership"

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then
owner=$(stat -L -c "%U" "$dir")
if [ "$owner" != "$user" ]; then
echo "The home directory ($dir) of user $user is owned by $owner."
fi
fi
done



echo "=================================================================================="
echo "9.2.14 Check for Duplicate UIDs"

echo "The Output for the Audit of Control 9.2.14- Check for Duplicate UIDs is"
/bin/cat /etc/passwd | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |while read x ; do [ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
users=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | /usr/bin/xargs`
echo "Duplicate UID ($2): ${users}"
fi
done





echo "=================================================================================="
echo "9.2.15 Check for Duplicate GIDs"

echo "The Output for the Audit of Control 9.2.15 - Check for Duplicate GIDs is"
/bin/cat /etc/group | /bin/cut -f3 -d":" | /bin/sort -n | /bin/uniq -c |while read x ; do [ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
grps=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
echo "Duplicate GID ($2): ${grps}"
fi
done




echo "=================================================================================="
echo "9.2.16 Check That Reserved UIDs Are Assigned to System Accounts"

defUsers="root bin daemon adm lp sync shutdown halt mail news uucp operator games gopher ftp nobody nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid named xfs gdm sabayon usbmuxd rtkit abrt saslauth pulse postfix tcpdump"
/bin/cat /etc/passwd |/bin/awk -F: '($3 < 1000) { print $1" "$3 }' | while read user uid; do found=0
for tUser in ${defUsers}
do
if [ ${user} = ${tUser} ]; then
found=1
fi
done
if [ $found -eq 0 ]; then
echo "User $user has a reserved UID ($uid)."
fi
done

echo "=================================================================================="
echo "9.2.17 Check for Duplicate User Names"
echo "The Output for the Audit of Control 9.2.18 - Check for Duplicate User Names is" 
cat /etc/passwd | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
	while read x ; do
	[ -z "${x}" ] && break 
	set - $x
	if [ $1 -gt 1 ]; then
		uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \ 
			/etc/passwd | xargs`
		echo "Duplicate User Name ($2): ${uids}" 
	fi
done
echo "=================================================================================="
echo "9.2.18 Check for Duplicate Group Names"
echo "The Output for the Audit of Control 9.2.19 - Check for Duplicate Group Names is" 
cat /etc/group | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
	while read x ; do
	[ -z "${x}" ] && break 
	set - $x
	if [ $1 -gt 1 ]; then
		gids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \ 
		/etc/group | xargs`
		echo "Duplicate Group Name ($2): ${gids}" 
	fi
done

echo "=================================================================================="
echo "9.2.19 Check for Presence of User .netrc Files"
echo "----"
for dir in `/bin/cat /etc/passwd |\
	/bin/awk -F: '{ print $6 }'`; do
	if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
		echo ".netrc file $dir/.netrc exists" 
	fi
done

echo "=================================================================================="
echo "9.2.20 Check for Presence of User .forward Files"
echo "----"
for dir in `/bin/cat /etc/passwd |\
	/bin/awk -F: '{ print $6 }'`; do
		if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then 
			echo ".forward file $dir/.forward exists"
		fi
done
echo "=================================================================================="
echo "Auditing is Completed"
