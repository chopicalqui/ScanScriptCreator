#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "This script must run as root" 
    exit 1
fi

if [ -z "$1" ]; then
	echo "usage: $0 <IP|DNS|hosts file> [directory for log files]"
	exit 1
fi

if [ -z "$2" ]; then
    path="./"
elif [ "${2:${#2}-1:1}" != "/" ]; then
    path="$2/"
else
    path="$2"
fi

if [ -e "$1" ]; then
	hosts="-iL $1"
	test_host=$(head -n 1 $1)
else
	hosts="$1"
	test_host="$1"
fi

# log the scanner's IP address configuration
ifconfig > ipconfig.txt
route -n > route-n.txt



# Initialization of Interesting Ports List
telnet=23,107
ftp=20,21
ssh=22
msprc=135
smtp=25,465,587
domain=53
tftp=69
http=80,443,1080,4343,4433,5357,5800,8014,8080,8081,8082,8088,8443,8888,9090,10000
pop=109,110
rpcbind=111
adds=88,389,363,464,636,3268,3269
sftp=115
snmp=161
smb=139,445
vpn=500
imap=143,993
rlogin=513
rmi=1099,1100
mssql=1433,1434
oracle=1030,1046,1289,1521,1658,1830,5500,5501,5522,5560,5580,7443
nfs=2049
mysql=3306
rdp=3389
postgresql=5432
x11=6000,6001,6002,6003,6004,6005
sip=5060,5061
vnc=5800,5801,5802,5803,5900,5901,5902,5903
mongodb=27017,27018,27019
elastic=9200,9300
couchdb=5984
neo4j=7473,7474
winrm=5985,5986
dhcp=68
tftp=69
rpcbind=111
ntp=123
snmp=161
vpn=500
ipmi=623
nfs=2049
domain=53,5353
mssql=1433,1434
vnc=5900
x11=6000-6005

tcp_ports="$telnet,$ftp,$ssh,$msprc,$smtp,$domain,$tftp,$http,$pop,$rpcbind,$adds,$sftp,$snmp,$smb,$vpn,$imap,$rlogin,$rmi,$mssql,$oracle,$nfs,$mysql,$rdp,$postgresql,$x11,$sip,$vnc,$mongodb,$elastic,$couchdb,$neo4j,$winrm"
udp_ports="$dhcp,$tftp,$rpcbind,$ntp,$snmp,$vpn,$ipmi,$nfs,$domain,$mssql,$vnc,$x11"


# Initialization of Default NSE Scripts List
tcp_scripts="--script fingerprint-strings,banner"
udp_scripts="--script fingerprint-strings,banner"


# Initialization of Nmap Options
nmap_options="-Pn -v --stats-every 10 --reason -sV --max-retries 1 --min-hostgroup 64 --traceroute"
nmap_tcp_options="-sS --defeat-rst-ratelimit"
nmap_udp_options="-sU --defeat-icmp-ratelimit"


# Initialization of Nmap Executable Path
nmap=nmap

# Updating NSE Database
"$nmap" --script-updatedb


# Scan Interesting TCP Ports
command="$nmap $nmap_tcp_options $nmap_options -O -p $tcp_ports $timing_options $exclude_hosts $tcp_scripts $hosts -oA ${path}nmap-tcp-interesting_${1/\//-}"
echo $command
$command
# Scan Interesting UDP Ports
command="$nmap $nmap_udp_options $nmap_options -n -p $udp_ports $timing_options $exclude_hosts $udp_scripts $hosts -oA ${path}nmap-udp-interesting_${1/\//-}"
echo $command
$command
# Scan All TCP Ports
command="$nmap $nmap_tcp_options $nmap_options -n -p- --exclude-ports $tcp_ports $timing_options $exclude_hosts $tcp_scripts $hosts -oA ${path}nmap-tcp-remaining_${1/\//-}"
echo $command
$command
# Scan Top 100 UDP Ports
command="$nmap $nmap_udp_options $nmap_options -n --top-ports 100 --exclude-ports $udp_ports $timing_options $exclude_hosts $udp_scripts $hosts -oA ${path}nmap-udp-remaining-top100_${1/\//-}"
echo $command
$command

exit 0
