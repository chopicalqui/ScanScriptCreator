@echo off

if "%1"=="" goto :Help
set hosts=%1
if exist %1 set hosts=-iL %1

set filepart=%1
set filepart=%filepart:/=_%
      
set nmap=C:\Program Files (x86)\nmap\nmap.exe
if not exist "%nmap%" goto:NmapNotExists

rem log the scanner's IP address configuration
ipconfig /ALL > ipconfig.txt
route PRINT > route-print.txt


rem Initialization of Interesting Ports List
set telnet=23,107
set ftp=20,21
set ssh=22
set msprc=135
set smtp=25,465,587
set domain=53
set tftp=69
set http=80,443,1080,4343,4433,5357,5800,8014,8080,8081,8082,8088,8443,8888,9090,10000
set pop=109,110
set rpcbind=111
set adds=88,389,363,464,636,3268,3269
set sftp=115
set snmp=161
set smb=139,445
set vpn=500
set imap=143,993
set rlogin=513
set rmi=1099,1100
set mssql=1433,1434
set oracle=1030,1046,1289,1521,1658,1830,5500,5501,5522,5560,5580,7443
set nfs=2049
set mysql=3306
set rdp=3389
set postgresql=5432
set x11=6000,6001,6002,6003,6004,6005
set sip=5060,5061
set vnc=5800,5801,5802,5803,5900,5901,5902,5903
set mongodb=27017,27018,27019
set winrm=5985,5986
set dhcp=68
set tftp=69
set rpcbind=111
set ntp=123
set snmp=161
set vpn=500
set ipmi=623
set nfs=2049
set domain=53,5353
set mssql=1433,1434
set vnc=5900
set x11=6000-6005

set tcp_ports=%telnet%,%ftp%,%ssh%,%msprc%,%smtp%,%domain%,%tftp%,%http%,%pop%,%rpcbind%,%adds%,%sftp%,%snmp%,%smb%,%vpn%,%imap%,%rlogin%,%rmi%,%mssql%,%oracle%,%nfs%,%mysql%,%rdp%,%postgresql%,%x11%,%sip%,%vnc%,%mongodb%,%winrm%
set udp_ports=%dhcp%,%tftp%,%rpcbind%,%ntp%,%snmp%,%vpn%,%ipmi%,%nfs%,%domain%,%mssql%,%vnc%,%x11%


rem Initialization of Default NSE Scripts List
set tcp_scripts= --script fingerprint-strings
set udp_scripts= --script fingerprint-strings


rem Initialization of Nmap Options
set nmap_options=-Pn -v --stats-every 10 --reason -sV --max-retries 1 --min-hostgroup 64 --traceroute
set nmap_tcp_options=-sS --defeat-rst-ratelimit
set nmap_udp_options=-sU --defeat-icmp-ratelimit


rem  Updating NSE Database
"%nmap%" --script-updatedb
echo No timing options specified; using default settings


rem Scan Interesting TCP Ports
set command="%nmap%" %nmap_tcp_options% %nmap_options% -O -p %tcp_ports% %timing_options% %exclude_hosts% %tcp_scripts% %hosts% -oA nmap-tcp-interesting
echo %command%
%command%
rem Scan Interesting UDP Ports
set command="%nmap%" %nmap_udp_options% %nmap_options% -n -p %udp_ports% %timing_options% %exclude_hosts% %udp_scripts% %hosts% -oA nmap-udp-interesting
echo %command%
%command%
rem Scan All TCP Ports
set command="%nmap%" %nmap_tcp_options% %nmap_options% -n -p- --exclude-ports %tcp_ports% %timing_options% %exclude_hosts% %tcp_scripts% %hosts% -oA nmap-tcp-remaining
echo %command%
%command%
rem Scan Top 100 UDP Ports
set command="%nmap%" %nmap_udp_options% %nmap_options% -n --top-ports 100 --exclude-ports %udp_ports% %timing_options% %udp_scripts% %hosts% -oA nmap-udp-remaining-top100
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
