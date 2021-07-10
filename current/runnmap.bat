@echo off

if "%1"=="" goto :Help
set hosts=%1
if exist %1 set hosts=-iL %1

set filepart=%1
set filepart=%filepart:/=_%

set nmap=C:\Program Files (x86)\nmap\nmap.exe
if not exist "%nmap%" goto:NmapNotExists

rem log the scanner's IP address configuration
set timestamp=%date:~10,4%%date:~4,2%%date:~7,2%-%time:~0,2%%time:~3,2%%time:~6,2%_
ipconfig /ALL > %timestamp%ipconfig.txt
route PRINT > %timestamp%route-print.txt


rem Initialization of Interesting Ports List
set tcp_telnet=23,107
set tcp_ftp=20,21
set tcp_ssh=22
set tcp_msprc=135
set tcp_smtp=25,465,587
set tcp_domain=53
set tcp_tftp=69
set tcp_http=80,443,1080,4343,4433,5357,8014,8080,8081,8082,8088,8443,8888,9090,10000
set tcp_pop=109,110
set tcp_rpcbind=111
set tcp_adds=88,389,363,464,636,3268,3269
set tcp_sftp=115
set tcp_snmp=161
set tcp_smb=139,445
set tcp_vpn=500
set tcp_imap=143,993
set tcp_rlogin=513
set tcp_rmi=1099,1100
set tcp_mssql=1433,1434
set tcp_oracle=1030,1046,1289,1521,1658,1830,5500,5501,5522,5560,5580,7443
set tcp_mqtt=1883,8883
set tcp_nfs=2049
set tcp_mysql=3306
set tcp_rdp=3389
set tcp_postgresql=5432
set tcp_x11=6000-6005
set tcp_sip=5060,5061
set tcp_vnc=5800-5803,5900-5903
set tcp_mongodb=27017-27019
set tcp_elastic=9200,9300
set tcp_couchdb=5984
set tcp_neo4j=7473,7474
set tcp_winrm=5985,5986
set udp_dhcp=68
set udp_tftp=69
set udp_rpcbind=111
set udp_ntp=123
set udp_snmp=161
set udp_vpn=500
set udp_ipmi=623
set udp_nfs=2049
set udp_domain=53,5353
set udp_mssql=1433,1434
set udp_vnc=5900
set udp_x11=6000-6005

set tcp_ports=%tcp_telnet%,%tcp_ftp%,%tcp_ssh%,%tcp_msprc%,%tcp_smtp%,%tcp_domain%,%tcp_tftp%,%tcp_http%,%tcp_pop%,%tcp_rpcbind%,%tcp_adds%,%tcp_sftp%,%tcp_snmp%,%tcp_smb%,%tcp_vpn%,%tcp_imap%,%tcp_rlogin%,%tcp_rmi%,%tcp_mssql%,%tcp_oracle%,%tcp_mqtt%,%tcp_nfs%,%tcp_mysql%,%tcp_rdp%,%tcp_postgresql%,%tcp_x11%,%tcp_sip%,%tcp_vnc%,%tcp_mongodb%,%tcp_elastic%,%tcp_couchdb%,%tcp_neo4j%,%tcp_winrm%
set udp_ports=%udp_dhcp%,%udp_tftp%,%udp_rpcbind%,%udp_ntp%,%udp_snmp%,%udp_vpn%,%udp_ipmi%,%udp_nfs%,%udp_domain%,%udp_mssql%,%udp_vnc%,%udp_x11%


rem Initialization of Default NSE Scripts List
set tcp_scripts= --script fingerprint-strings,banner
set udp_scripts= --script fingerprint-strings,banner


rem Initialization of Nmap Options
set nmap_options=-Pn -v --stats-every 10 --reason -sV --max-retries 1 --min-hostgroup 64 --traceroute
set nmap_tcp_options=-sS --defeat-rst-ratelimit
set nmap_udp_options=-sU --defeat-icmp-ratelimit


rem  Updating NSE Database
"%nmap%" --script-updatedb
echo No timing options specified; using default settings


rem Scan Interesting TCP Ports
set command="%nmap%" %nmap_tcp_options% %nmap_options% -O -p %tcp_ports% %timing_options% %exclude_hosts% %tcp_scripts% %hosts% -oA %timestamp%nmap-tcp-interesting
echo %command%
%command%
rem Scan Interesting UDP Ports
set command="%nmap%" %nmap_udp_options% %nmap_options% -n -p %udp_ports% %timing_options% %exclude_hosts% %udp_scripts% %hosts% -oA %timestamp%nmap-udp-interesting
echo %command%
%command%
rem Scan All TCP Ports
set command="%nmap%" %nmap_tcp_options% %nmap_options% -n -p- --exclude-ports %tcp_ports% %timing_options% %exclude_hosts% %tcp_scripts% %hosts% -oA %timestamp%nmap-tcp-remaining
echo %command%
%command%
rem Scan Top 100 UDP Ports
set command="%nmap%" %nmap_udp_options% %nmap_options% -n --top-ports 100 --exclude-ports %udp_ports% %timing_options% %udp_scripts% %hosts% -oA %timestamp%nmap-udp-remaining-top100
echo %command%
%command%

goto :End

:NmapNotExists
echo Nmap "%nmap%" does not exist!
goto :End

:Help
echo "usage: %0 <IP|DNS|hosts file>"
goto :End

:End
pause
