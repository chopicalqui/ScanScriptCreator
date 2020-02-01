# Nmap Script Creator

This script creates a Bash or DOS script to scan networks using [Nmap Security Scanner](https://nmap.org/) or 
[Masscan](https://github.com/robertdavidgraham/masscan). If Nmap is selected, then the created Bash or DOS script 
performs four scans. The first two Nmap commands, scan only the most promising TCP and UDP ports, which are specified 
in the script's configuration file (see 
[createscanfile.config](https://github.com/chopicalqui/scanfilecreator/blob/master/sfc/createscanfile.config)), 
sections `InterestingTcpPorts` and `InterestingUdpPorts`. Afterwards, in case of TCP, all remaining TCP ports are 
scanned. The final command scans the remaining top 100 UDP ports (use `--top-udp` flag to change this default 
configuration). If Masscan is selected, then the created Bash script (no DOS support) performs two scans. The first 
scan, scans all targets for the most promising TCP ports (see `InterestingTcpPorts`) and the second scans all TCP ports.


## Objective

During penetration tests, we usually do not have time to completely scan the entire network in scope. In addition, as
we want to manually start penetration testing as soon as possible, we would like to have scan results as fast as 
possible as well. Consequently, this script creates a Nmap or Masscan scan script, that aid in the fast identification 
of interesting services (e.g., FTP, HTTP, etc.) but still continues scanning the remaining ports.

Note that this script only creates Nmap and Masscan script files but does not execute the Nmap or Masscan scripts 
directly for the following two reasons:

  * On the scan machine itself, just Nmap or Masscan and not Python3 must be installed
  * After the generation of the Nmap or Masscan script, penetration testers are still able to review and customize the 
  Nmap or Masscan scripts to their specific needs


## Standard Operating Procedure

The following example shows my standard operating procedure for scanning a network. 

For external and remote networks, I determine the maximum round trip time (RTT) by sending 20 SYN packets to a known 
open port of one of the hosts within the target network range. 

```bash
root@kali:~# hping3 -c 20 --syn -p 80 $target
[...]
round-trip min/avg/max = 10.2/20.1/35.4 ms
```

Afterwards, I create the Nmap scan file and specify the measured maximum RTT (see previous command) as value for the 
`--avg-rtt` argument. Based on this argument, the script will compute the Nmap timing according to the blog post 
[Timing and Performance](https://nmap.org/book/man-performance.html). The Nmap timing is specified by the variable 
`timing_options` in the scan file `runnmap.sh`. If I am dealing with a local network where my own IP addresses are also 
within the scope, I also use argument `--exclude` to exclude these IP addresses from the scan.

```bash
root@kali:~# python3 createscan.py --bash nmap --avg-rtt 35 --udp-port 100 > runnmap.sh
```

Before executing the script, review the content of the newly created scan file `runnmap.sh` and if desired change 
like variable `nmap_options` (e.g., removing option `-Pn` or adding `-T4`). In addition, it might be desired to remove 
certain scans (like remaining TCP ports). If everything is alright, the scan can be started by executing the following 
commands.

```bash
root@kali:~# chmod +x runnmap.sh
# execute all hosts mentioned in file hosts.txt
root@kali:~# ./runnmap.sh hosts.txt
# or execute scan on single host
root@kali:~# ./runnmap.sh 127.0.0.1
```

As mentioned before, this script executes four Nmap or two Masscan scans. Each scan creates three output files 
(nmap, gnmap, and xml).  As soon as one of the scans finishes, you can start doing your work. Alternatively, you can 
import the created XML file(s) into [Kali Intel Suite](https://github.com/chopicalqui/kaliintelsuite), as depicted 
below, which allows you to automatically perform additional intel gathering tasks based on Nmap's scan results. For 
more information, refer to [README](https://github.com/chopicalqui/kaliintelsuite/blob/master/README.md).

```bash
root@kali:~# kismanage workspace -a $workspace
root@kali:~# kismanage scan -w $workspace --nmap *.xml
[*] Importing XML file: nmap-udp-remaining-top100_hosts.txt.xml
[*] Importing XML file: nmap-tcp-remaining_hosts.txt.xml
[*] Importing XML file: nmap-tcp-interesting_hosts.txt.xml
[*] Importing XML file: nmap-udp-interesting_hosts.txt.xml
```


## Author

  * **Lukas Reiter** - *Initial Work* - [createscanfiles](https://github.com/chopicalqui/scanfilecreator)


## License

This project is licensed under the GPLv3 License - see the 
[LICENSE](https://github.com/chopicalqui/scanfilecreator/blob/master/LICENSE) file for details.

