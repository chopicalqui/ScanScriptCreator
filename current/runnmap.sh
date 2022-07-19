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
timestamp=`date '+%Y%m%d-%H%M%S'`_`hostname`
ifconfig > ${timestamp}_ipconfig.txt
route -n > ${timestamp}_route-n.txt



# Initialization of Interesting Ports List
tcp_telnet=23,107
tcp_ftp=20,21
tcp_ssh=22
tcp_msprc=135
tcp_smtp=25,465,587
tcp_domain=53
tcp_tftp=69
tcp_http=80,443,1080,4343,4433,5357,8014,8080,8081,8082,8088,8443,8888,9090,10000
tcp_pop=109,110
tcp_rpcbind=111
tcp_adds=88,389,363,464,636,3268,3269
tcp_sftp=115
tcp_snmp=161
tcp_smb=139,445
tcp_vpn=500
tcp_imap=143,993
tcp_rlogin=513
tcp_rmi=1099,1100
tcp_mssql=1433,1434
tcp_oracle=1030,1046,1289,1521,1658,1830,5500,5501,5522,5560,5580,7443
tcp_mqtt=1883,8883
tcp_nfs=2049
tcp_mysql=3306
tcp_rdp=3389
tcp_postgresql=5432
tcp_x11=6000-6005
tcp_sip=5060,5061
tcp_vnc=5800-5803,5900-5903
tcp_mongodb=27017-27019
tcp_elastic=9200,9300
tcp_couchdb=5984
tcp_neo4j=7473,7474
tcp_winrm=5985,5986
udp_dhcp=68
udp_tftp=69
udp_rpcbind=111
udp_ntp=123
udp_snmp=161
udp_vpn=500
udp_ipmi=623
udp_nfs=2049
udp_domain=53,5353
udp_mssql=1433,1434
udp_vnc=5900
udp_x11=6000-6005

tcp_ports="$tcp_telnet,$tcp_ftp,$tcp_ssh,$tcp_msprc,$tcp_smtp,$tcp_domain,$tcp_tftp,$tcp_http,$tcp_pop,$tcp_rpcbind,$tcp_adds,$tcp_sftp,$tcp_snmp,$tcp_smb,$tcp_vpn,$tcp_imap,$tcp_rlogin,$tcp_rmi,$tcp_mssql,$tcp_oracle,$tcp_mqtt,$tcp_nfs,$tcp_mysql,$tcp_rdp,$tcp_postgresql,$tcp_x11,$tcp_sip,$tcp_vnc,$tcp_mongodb,$tcp_elastic,$tcp_couchdb,$tcp_neo4j,$tcp_winrm"
udp_ports="$udp_dhcp,$udp_tftp,$udp_rpcbind,$udp_ntp,$udp_snmp,$udp_vpn,$udp_ipmi,$udp_nfs,$udp_domain,$udp_mssql,$udp_vnc,$udp_x11"


# Initialization of Default NSE Scripts List
tcp_scripts="--script fingerprint-strings,banner"
udp_scripts="--script fingerprint-strings,banner"


# Initialization of Nmap Options
nmap_options="-Pn -v --stats-every 10 --reason --max-retries 1 --min-hostgroup 64 --traceroute -e $iface"
nmap_tcp_options="-sSV --defeat-rst-ratelimit"
nmap_udp_options="-sUV --defeat-icmp-ratelimit"


# Initialization of Nmap Executable Path
nmap=nmap

# Updating NSE Database
"$nmap" --script-updatedb


# Scan Interesting TCP Ports
command="$nmap $nmap_tcp_options $nmap_options -O -p $tcp_ports $timing_options $exclude_hosts $tcp_scripts $hosts -oA ${path}${timestamp}_nmap-tcp-interesting_${2/\//-}"
echo $command
$command
# Scan Interesting UDP Ports
command="$nmap $nmap_udp_options $nmap_options -n -p $udp_ports $timing_options $exclude_hosts $udp_scripts $hosts -oA ${path}${timestamp}_nmap-udp-interesting_${2/\//-}"
echo $command
$command
# Scan All TCP Ports
command="$nmap $nmap_tcp_options $nmap_options -n -p- --exclude-ports $tcp_ports $timing_options $exclude_hosts $tcp_scripts $hosts -oA ${path}${timestamp}_nmap-tcp-remaining_${2/\//-}"
echo $command
$command
# Scan Top 100 UDP Ports
command="$nmap $nmap_udp_options $nmap_options -n --top-ports 100 --exclude-ports $udp_ports $timing_options $exclude_hosts $udp_scripts $hosts -oA ${path}${timestamp}_nmap-udp-remaining-top100_${2/\//-}"
echo $command
$command

exit 0
