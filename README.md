# Nmap Script Creator

This script creates a Bash or DOS script to scan networks using [Nmap Security Scanner](https://nmap.org/) or 
[Masscan](https://github.com/robertdavidgraham/masscan).

If Nmap is selected, then the created Bash or DOS script performs four scans. The first two Nmap commands scan 
only the most promising TCP and UDP ports, which are specified  in the script's configuration file (see 
[createscanfile.config](https://github.com/chopicalqui/scanscriptcreator/blob/master/ssc/createscanscript.config)), 
sections `InterestingTcpPorts` and `InterestingUdpPorts`. Afterwards, in case of TCP, all remaining TCP ports are 
scanned. The final command scans the remaining top 100 UDP ports (use `--top-udp` flag to change this default 
configuration).

If Masscan is selected, then the created Bash script (no DOS support) performs two scans. The first scan, scans 
all targets for the most promising TCP ports (see `InterestingTcpPorts`) and the second scans all TCP ports.


## Objective

During penetration tests, we eventually do not have time to completely scan the entire network in scope. In addition, 
as we want to manually start penetration testing as soon as possible, we would like to have scan results as fast as 
possible. Consequently, this script creates a Nmap or Masscan scan script file, which aids in the fast identification 
of interesting services (e.g., FTP, HTTP, etc.) but still continues scanning the remaining ports for later analysis.

Note that this script only creates Nmap and Masscan script files but does not execute the Nmap or Masscan scripts 
directly for the following two reasons:

  * On the scan machine itself, just Nmap or Masscan and not Python3 must be installed
  * After the generation of the Nmap or Masscan script, penetration testers are still able to review and customize the 
  Nmap or Masscan scripts to their specific needs


## Standard Operating Procedures

This section summarize the standard operating procedure (SOP) for Masscan and Nmap.

In internal penetration tests, we eventually want to start scanning hosts that definitely exist. This can be 
accomplished by using the computer information collected via [Sharphound](https://github.com/BloodHoundAD/SharpHound). 
The following Bash command documents how we can query all enabled computer names from the Neo4j database and store the 
results in the file `hosts.txt`.

```bash
kali@kali:~$  cypher-shell --format plain -u neo4j 'MATCH(c:Computer{enabled: true}) WHERE c.name IS NOT NULL RETURN c.name;' | grep -v c.name | sed -e's/\"//g' > hosts.txt
```

The `hosts.txt` can then be used as input for the scan (see below). When these scans are completed, then we can 
continue scanning the remaining IP addresses to be as complete as possible.


### Masscan

The following example documents the SOP for scanning a network using Masscan. 

First, we create the template scan script file using the following command or download the 
[latest version](https://github.com/chopicalqui/ScanScriptCreator/blob/master/current/runmasscan.sh):

```bash
kali@kali:~$  python3 createscanscript.py --bash masscan > runmasscan.sh
```

Note that if we are dealing with a local network where our own IP addresses are also within the scope, we also use 
argument `--exclude` to exclude these IP addresses from the scan.

Before executing the script, we review the content of the newly created scan file `runmasscan.sh` and if desired, change 
variable `masscan_options` (e.g., remove option `-Pn` or update rate limit). In addition, it might be desired to remove 
certain scans (like remaining TCP ports). If everything is alright, we start the scan by executing the following 
commands:

```bash
kali@kali:~$  chmod +x runmasscan.sh
# scan all hosts mentioned in file hosts.txt via network interface eth0
kali@kali:~$  sudo ./runmasscan.sh eth0 hosts.txt
# or execute scan on single host
root@kali:~# ./runmasscan.sh eth0 127.0.0.1
```

As mentioned before, this script executes two Masscan scans. For each scan, the script creates one XML file. 
As soon as one of the scans finishes, you can start doing your vulnerability analysis. Alternatively, you can import 
the created XML file(s) into the [Kali Intelligence Suite (KIS)](https://github.com/chopicalqui/KaliIntelligenceSuite), 
as depicted below. For more information about KIS, 
refer to [README](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/README.md).

```bash
root@kali:~# kismanage workspace -a $workspace
root@kali:~# kismanage scan -w $workspace --masscan *.xml
[*] importing XML file: masscan-tcp-all_hosts.txt.xml
[*] importing XML file: masscan-tcp-interesting_hosts.txt.xml
```

### Nmap

The following example documents the SOP for scanning a network using Nmap.

For external and remote networks, we can determine the maximum round trip time (RTT) by sending 20 SYN packets to a 
known open port of one of the hosts within the target network range. 

```bash
root@kali:~# hping3 -c 20 --syn -p 80 $target
[...]
round-trip min/avg/max = 10.2/20.1/35.4 ms
```

Afterwards, we create the Nmap scan file and specify the measured maximum RTT (see previous command) as value for the 
`--avg-rtt` argument. Based on this argument, the script will compute the Nmap timing according to the blog post 
[Timing and Performance](https://nmap.org/book/man-performance.html). Alternatively, we can download and use the 
[latest version](https://github.com/chopicalqui/ScanScriptCreator/blob/master/current/runmasscan.sh):

```bash
root@kali:~# python3 createscanscript.py --bash nmap --avg-rtt 35 --udp-port 100 > runnmap.sh
```

Note that if we are dealing with a local network where our own IP addresses are also within the scope, we also use 
argument `--exclude` to exclude these IP addresses from the scan.

Before executing the script, review the content of the newly created scan file `runnmap.sh` and if desired, change 
variable `nmap_options` (e.g., remove option `-Pn` or add `-T4`). In addition, it might be desired to remove 
certain scans (like remaining TCP ports). If everything is alright, we start the scan by executing the following 
commands:

```bash
root@kali:~# chmod +x runnmap.sh
# scan all hosts mentioned in file hosts.txt via network interface eth0
root@kali:~# ./runnmap.sh eth0 hosts.txt
# or execute scan on single host
root@kali:~# ./runnmap.sh eth0 127.0.0.1
```

As mentioned before, this script executes four Nmap scans. Each scan, the script creates three output files 
(nmap, gnmap, and xml). As soon as one of the scans finishes, you can start doing your vulnerability analysis.
Alternatively, you can import the created XML file(s) into the 
[Kali Intelligence Suite (KIS)](https://github.com/chopicalqui/KaliIntelligenceSuite), as depicted below. For more 
information about KIS, refer to [README](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/README.md).

```bash
root@kali:~# kismanage workspace -a $workspace
root@kali:~# kismanage scan -w $workspace --nmap *.xml
[*] Importing XML file: nmap-udp-remaining-top100_hosts.txt.xml
[*] Importing XML file: nmap-tcp-remaining_hosts.txt.xml
[*] Importing XML file: nmap-tcp-interesting_hosts.txt.xml
[*] Importing XML file: nmap-udp-interesting_hosts.txt.xml
```


## Author

**Lukas Reiter** ([@chopicalquy](https://twitter.com/chopicalquy)) - 
[Scan Script Creator](https://github.com/chopicalqui/scanscriptcreator)


## License

This project is licensed under the GPLv3 License - see the 
[LICENSE](https://github.com/chopicalqui/scanscriptcreator/blob/master/LICENSE) file for details.

