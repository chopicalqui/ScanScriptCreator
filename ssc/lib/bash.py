# -*- coding: utf-8 -*-
"""
This module implements the functionality to create an Nmap scan file for Bash.
"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2018 Lukas Reiter

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
__version__ = 0.1

from lib.base import BaseScriptCreator
import os


class BaseNmapMasscanCreator(BaseScriptCreator):
    """Base class to create Nmap and Masscan scripts"""

    def __init__(self, config, args):
        super().__init__(config, args)

    def _get_pre_script(self):
        return """#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "This script must run as root" 
    exit 1
fi

if [ $# -lt 2 ]; then
	echo "usage: $0 <iface> <IP|DNS|hosts file> [directory for log files]"
    echo "  iface: The network interface used by Nmap. You can use the"
    echo "         following command to determine valid interfaces:"
    echo "         nmap --iflist "
	echo "  IP|DNS|hosts file: The target to be scanned."
	echo "directory for log files: Directory where Nmap shall save output."
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
elif [ "${{3:${{#2}}-1:1}}" != "/" ]; then
    path="$3/"
else
    path="$3"
fi

# Initialization of Nmap Executable Path
nmap={}

# log the scanner's IP address configuration
timestamp=`date '+%Y%m%d-%H%M%S'`_`hostname`
"$nmap" --iflist > "${{timestamp}}_iflist.log"

""".format(self._exec)

    def _get_post_script(self):
        return """
exit 0"""


class NmapScriptCreator(BaseNmapMasscanCreator):
    """This class implements all functionality to create an Nmap scan script for Bash"""

    def __init__(self, config, args):
        super().__init__(config, args)

    def _get_rtt_computation_script(self):
        if self._avg_rtt:
            return """

# Calculation of RTTs
echo "avg: {0} rtt_init: {1} rtt_max: {2} max_scan_delay: {3}"
timing_options="--initial-rtt-timeout {1}ms --max-rtt-timeout {2}ms --max-scan-delay {3}"
""".format(self._avg_rtt, self._nmap_rtt_factor_init * self._avg_rtt, self._nmap_rtt_factor_max * self._avg_rtt,
           self._nmap_max_scan_delay)
        else:
            return ""

    def _get_init_script_variables(self):
        rvalue = "{0}# Initialization of Interesting Ports List{0}".format(os.linesep)
        tcp_keys = []
        udp_keys = []
        for key, value in self._interesting_tcp:
            rvalue += "{}={}{}".format(key, value, os.linesep)
            tcp_keys.append("${}".format(key))
        for key, value in self._interesting_udp:
            rvalue += "{}={}{}".format(key, value, os.linesep)
            udp_keys.append("${}".format(key))

        rvalue += os.linesep
        rvalue += """tcp_ports=\"{}\"{}""".format(",".join(tcp_keys), os.linesep)
        rvalue += """udp_ports=\"{}\"{}""".format(",".join(udp_keys), os.linesep)
        rvalue += os.linesep

        rvalue += "{0}# Initialization of Default NSE Scripts List{0}".format(os.linesep)
        rvalue += """tcp_scripts=\"--script {}\"{}""".format(self._nmap_tcp_scripts, os.linesep)
        rvalue += """udp_scripts=\"--script {}\"{}""".format(self._nmap_udp_scripts, os.linesep)
        rvalue += os.linesep

        if self._args.exclude:
            rvalue += "{0}# Exclude hosts from scan{0}".format(os.linesep)
            rvalue += "exclude_hosts=\"--exclude {}\"{}".format(",".join(self._args.exclude), os.linesep)
            rvalue += os.linesep

        rvalue += "{0}# Initialization of Nmap Options{0}".format(os.linesep)
        rvalue += "nmap_options=\"{} -e $iface\"{}".format(self._nmap_options, os.linesep)
        rvalue += "nmap_tcp_options=\"{}\"{}".format(self._nmap_tcp_options, os.linesep)
        rvalue += "nmap_udp_options=\"{}\"{}".format(self._nmap_udp_options, os.linesep)
        rvalue += os.linesep

        rvalue += "{0}# Updating NSE Database{0}".format(os.linesep)
        rvalue += "\"$nmap\" --script-updatedb{}".format(os.linesep)

        return rvalue

    def _get_interesting_tcp(self):
        rvalue = "# Scan Interesting TCP Ports{}".format(os.linesep)
        rvalue += "command=\"$nmap $nmap_tcp_options $nmap_options {} -p $tcp_ports $timing_options " \
                  "$exclude_hosts $tcp_scripts $hosts -oA " \
                  "${{path}}${{timestamp}}_nmap-tcp-interesting_${{2/\\//-}}\"{}".format(self._first_run_options,
                                                                                         os.linesep)
        rvalue += "echo $command{}".format(os.linesep)
        rvalue += "$command"
        return rvalue

    def _get_remaining_tcp(self):
        rvalue = "# Scan All TCP Ports{}".format(os.linesep)
        rvalue += "command=\"$nmap $nmap_tcp_options $nmap_options {} -p- " \
                  "--exclude-ports $tcp_ports $timing_options $exclude_hosts $tcp_scripts $hosts " \
                  "-oA ${{path}}${{timestamp}}_nmap-tcp-remaining_${{2/\\//-}}\"{}".format(self._nmap_options_not_first_run,
                                                                                           os.linesep)
        rvalue += "echo $command{}".format(os.linesep)
        rvalue += "$command"
        return rvalue

    def _get_top_tcp(self):
        rvalue = "# Scan Top {} TCP Ports{}".format(self._top_tcp, os.linesep)
        rvalue += "command=\"$nmap $nmap_tcp_options $nmap_options {0} --top-ports {1} --exclude-ports $tcp_ports " \
                  "$timing_options $exclude_hosts $tcp_scripts $hosts -oA " \
                  "${{path}}${{timestamp}}_nmap-tcp-remaining-top{1}_${{2/\\//-}}\"{2}".format(self._nmap_options_not_first_run,
                                                                                               self._top_tcp,
                                                                                               os.linesep)
        rvalue += "echo $command{}".format(os.linesep)
        rvalue += "$command"
        return rvalue

    def _get_interesting_udp(self):
        rvalue = "# Scan Interesting UDP Ports{}".format(os.linesep)
        rvalue += "command=\"$nmap $nmap_udp_options $nmap_options {} -p $udp_ports $timing_options " \
                  "$exclude_hosts $udp_scripts $hosts -oA " \
                  "${{path}}${{timestamp}}_nmap-udp-interesting_${{2/\\//-}}\"{}".format(self._nmap_options_not_first_run,
                                                                                         os.linesep)
        rvalue += "echo $command{}".format(os.linesep)
        rvalue += "$command"
        return rvalue

    def _get_top_udp(self):
        rvalue = "# Scan Top {} UDP Ports{}".format(self._top_udp, os.linesep)
        rvalue += "command=\"$nmap $nmap_udp_options $nmap_options {0} --top-ports {1} --exclude-ports $udp_ports " \
                  "$timing_options $exclude_hosts $udp_scripts $hosts -oA " \
                  "${{path}}${{timestamp}}_nmap-udp-remaining-top{1}_${{2/\\//-}}\"{2}".format(self._nmap_options_not_first_run,
                                                                                               self._top_udp,
                                                                                               os.linesep)
        rvalue += "echo $command{}".format(os.linesep)
        rvalue += "$command"
        return rvalue


class MasscanScriptCreator(BaseNmapMasscanCreator):
    """This class implements all functionality to create an Masscan scan script for Bash"""

    def __init__(self, config, args):
        super().__init__(config, args)

    def _get_rtt_computation_script(self):
            return ""

    def _get_init_script_variables(self):
        rvalue = "{0}# Initialization of Interesting Ports List{0}".format(os.linesep)
        tcp_keys = []
        for key, value in self._interesting_tcp:
            rvalue += "{}={}{}".format(key, value, os.linesep)
            tcp_keys.append("${}".format(key))

        rvalue += os.linesep
        rvalue += """tcp_ports=\"{}\"{}""".format(",".join(tcp_keys), os.linesep)
        rvalue += os.linesep

        if self._args.exclude:
            rvalue += "{0}# Exclude hosts from scan{0}".format(os.linesep)
            rvalue += "exclude_hosts=\"--exclude {}\"{}".format(self._args.exclude[0], os.linesep)
            rvalue += os.linesep

        rvalue += "{0}# Initialization of Nmap Options{0}".format(os.linesep)
        rvalue += "masscan_options=\"{} -e $iface\"{}".format(self._masscan_general_options, os.linesep)
        rvalue += os.linesep

        rvalue += "{0}# Initialization of Nmap Executable Path{0}".format(os.linesep)
        rvalue += "masscan={}".format(self._exec, os.linesep)
        rvalue += os.linesep

        return rvalue

    def _get_interesting_tcp(self):
        rvalue = "# Scan Interesting TCP Ports{}".format(os.linesep)
        rvalue += "command=\"$masscan $masscan_options -sS -p $exclude_hosts $tcp_ports $hosts -oX " \
                  "${{path}}${{timestamp}}_masscan-tcp-interesting_${{2/\\//-}}.xml\"{}".format(os.linesep)
        rvalue += "echo $command{}".format(os.linesep)
        rvalue += "$command"
        return rvalue

    def _get_remaining_tcp(self):
        rvalue = "# Scan All TCP Ports{}".format(os.linesep)
        rvalue += "command=\"$masscan $masscan_options -sS -p 0-65535 $exclude_hosts $hosts -oX " \
                  "${{path}}${{timestamp}}_masscan-tcp-all_${{2/\\//-}}.xml\"{}".format(os.linesep)
        rvalue += "echo $command{}".format(os.linesep)
        rvalue += "$command"
        return rvalue

    def _get_top_tcp(self):
        return ""

    def _get_interesting_udp(self):
        return ""

    def _get_top_udp(self):
        return ""
