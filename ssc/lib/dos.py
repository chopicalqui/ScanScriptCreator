# -*- coding: utf-8 -*-
"""
This module implements the functionality to create an Nmap scan file for DOS.
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


class NmapScriptCreator(BaseScriptCreator):
    def __init__(self, config, args):
        super().__init__(config, args)


    def _get_pre_script(self):
        return """@echo off

if "%1"=="" goto :Help
set hosts=%1
if exist %1 set hosts=-iL %1

set filepart=%1
set filepart=%filepart:/=_%
      
set nmap={}
if not exist "%nmap%" goto:NmapNotExists

rem log the scanner's IP address configuration
set timestamp=%date:~10,4%%date:~4,2%%date:~7,2%-%time:~0,2%%time:~3,2%%time:~6,2%_
ipconfig /ALL > %timestamp%ipconfig.txt
route PRINT > %timestamp%route-print.txt
""".format(self._exec)

    def _get_post_script(self):
        return """
goto :End

:NmapNotExists
echo Nmap "%nmap%" does not exist!
goto :End

:Help
echo "usage: %0 <IP|DNS|hosts file>"
goto :End

:End
pause"""

    def _get_rtt_computation_script(self):
        if self._avg_rtt:
            return """rem Calculation of RTTs
echo "avg: {0} rtt_init: {1} rtt_max: {2} max_scan_delay: {3}"
set timing_options="--initial-rtt-timeout {1}ms --max-rtt-timeout {2}ms --max-scan-delay {3}"
""".format(self._avg_rtt,
           self._nmap_rtt_factor_init * self._avg_rtt,
           self._nmap_rtt_factor_max * self._avg_rtt,
           self._nmap_max_scan_delay)
        else:
            return """echo No timing options specified; using default settings
"""

    def _get_init_script_variables(self):
        rvalue = "{0}rem Initialization of Interesting Ports List{0}".format(os.linesep)
        tcp_keys = []
        udp_keys = []
        for key, value in self._interesting_tcp:
            rvalue += "set {}={}{}".format(key, value, os.linesep)
            tcp_keys.append("%{}%".format(key))
        for key, value in self._interesting_udp:
            rvalue += "set {}={}{}".format(key, value, os.linesep)
            udp_keys.append("%{}%".format(key))

        rvalue += os.linesep
        rvalue += "set tcp_ports=" + ",".join(tcp_keys) + os.linesep
        rvalue += "set udp_ports=" + ",".join(udp_keys) + os.linesep
        rvalue += os.linesep

        rvalue += "{0}rem Initialization of Default NSE Scripts List{0}".format(os.linesep)
        rvalue += "set tcp_scripts= --script " + self._nmap_tcp_scripts + os.linesep
        rvalue += "set udp_scripts= --script " + self._nmap_udp_scripts + os.linesep
        rvalue += os.linesep

        if self._args.exclude:
            rvalue += "{0}rem Exclude hosts from scan{0}".format(os.linesep)
            rvalue += "set exclude_hosts=--exclude {}{}".format(",".join(self._args.exclude), os.linesep)
            rvalue += os.linesep

        rvalue += "{0}rem Initialization of Nmap Options{0}".format(os.linesep)
        rvalue += "set nmap_options={}{}".format(self._nmap_options, os.linesep)
        rvalue += "set nmap_tcp_options={}{}".format(self._nmap_tcp_options, os.linesep)
        rvalue += "set nmap_udp_options={}{}".format(self._nmap_udp_options, os.linesep)
        rvalue += os.linesep

        rvalue += "{0}rem  Updating NSE Database{0}".format(os.linesep)
        rvalue += "\"%nmap%\" --script-updatedb{}".format(os.linesep)

        return rvalue


    def _get_interesting_tcp(self):
        rvalue = "rem Scan Interesting TCP Ports{}".format(os.linesep)
        rvalue += "set command=\"%nmap%\" %nmap_tcp_options% %nmap_options% {} -p %tcp_ports% " \
                  "%timing_options% %exclude_hosts% %tcp_scripts% %hosts% -oA " \
                  "%timestamp%nmap-tcp-interesting{}".format(self._first_run_options,
                                                             os.linesep)
        rvalue += "echo %command%{}".format(os.linesep)
        rvalue += "%command%"
        return rvalue

    def _get_remaining_tcp(self):
        rvalue = "rem Scan All TCP Ports{}".format(os.linesep)
        rvalue += "set command=\"%nmap%\" %nmap_tcp_options% %nmap_options% {} -p- --exclude-ports " \
                  "%tcp_ports% %timing_options% %exclude_hosts% %tcp_scripts% %hosts% -oA " \
                  "%timestamp%nmap-tcp-remaining{}".format(self._nmap_options_not_first_run,
                                                           os.linesep)
        rvalue += "echo %command%{}".format(os.linesep)
        rvalue += "%command%"
        return rvalue

    def _get_top_tcp(self):
        rvalue = "rem Scan Top {} TCP Ports{}".format(self._top_tcp, os.linesep)
        rvalue += "set command=\"%nmap%\" %nmap_tcp_options% %nmap_options% {0} --top-ports {1} --exclude-ports " \
                  "%tcp_ports% %timing_options% %tcp_scripts% %hosts% -oA " \
                  "%timestamp%nmap-tcp-remaining-top{1}{2}".format(self._nmap_options_not_first_run,
                                                                   self._top_tcp,
                                                                   os.linesep)
        rvalue += "echo %command%{}".format(os.linesep)
        rvalue += "%command%"
        return rvalue

    def _get_interesting_udp(self):
        rvalue = "rem Scan Interesting UDP Ports{}".format(os.linesep)
        rvalue += "set command=\"%nmap%\" %nmap_udp_options% %nmap_options% {} -p %udp_ports% %timing_options% " \
                  "%exclude_hosts% %udp_scripts% %hosts% -oA " \
                  "%timestamp%nmap-udp-interesting{}".format(self._nmap_options_not_first_run,
                                                             os.linesep)
        rvalue += "echo %command%{}".format(os.linesep)
        rvalue += "%command%"
        return rvalue

    def _get_top_udp(self):
        rvalue = "rem Scan Top {} UDP Ports{}".format(self._top_udp, os.linesep)
        rvalue += "set command=\"%nmap%\" %nmap_udp_options% %nmap_options% {0} --top-ports {1} --exclude-ports " \
                  "%udp_ports% %timing_options% %udp_scripts% %hosts% -oA " \
                  "%timestamp%nmap-udp-remaining-top{1}{2}".format(self._nmap_options_not_first_run,
                                                                   self._top_udp,
                                                                   os.linesep)
        rvalue += "echo %command%{}".format(os.linesep)
        rvalue += "%command%"
        return rvalue
