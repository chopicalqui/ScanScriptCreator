#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "This script must run as root"
    exit 1
fi

if [ $# -lt 2 ]; then
	echo "usage: $0 <IFACE> <IP|DNS|hosts file> [directory for log files]"
	exit 1
fi

iface=$1

if [ -e "$2" ]; then
	hosts="-iL $2"
	test_host=$(head -n 1 $2)
else
	hosts="$2"
	test_host="$2"
fi

if [ -z "$3" ]; then
    path="./"
elif [ "${3:${#2}-1:1}" != "/" ]; then
    path="$3/"
else
    path="$3"
fi

# log the scanner's IP address configuration
timestamp=`date '+%Y%m%d-%H%M%S'`
ifconfig > ${timestamp}_ipconfig.txt
route -n > ${timestamp}_route-n.txt



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

tcp_ports="$telnet,$ftp,$ssh,$msprc,$smtp,$domain,$tftp,$http,$pop,$rpcbind,$adds,$sftp,$snmp,$smb,$vpn,$imap,$rlogin,$rmi,$mssql,$oracle,$nfs,$mysql,$rdp,$postgresql,$x11,$sip,$vnc,$mongodb,$elastic,$couchdb,$neo4j,$winrm"


# Initialization of Nmap Options
masscan_options="-Pn -v --open --banners --rate 1000 -e $iface"


# Initialization of Nmap Executable Path
masscan=masscan


# Scan Interesting TCP Ports
command="$masscan $masscan_options -sS -p $exclude_hosts $tcp_ports $hosts -oX ${path}masscan-tcp-interesting_${2/\//-}.xml"
echo $command
$command

# Scan All TCP Ports
command="$masscan $masscan_options -sS -p 0-65535 $exclude_hosts $hosts -oX ${path}masscan-tcp-all_${2/\//-}.xml"
echo $command
$command


exit 0