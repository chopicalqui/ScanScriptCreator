# -*- coding: utf-8 -*-
"""
This module implements base functionality for creating Nmap and Masscan scripts for various operating systems.
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

import re
import os


class BaseScriptCreator:
    """This class implements all base functionality to create an Nmap and Masscan scripts for specific languages."""

    def __init__(self, config, args):
        self._config = config
        self._interesting_tcp = [("tcp_" + item[0], item[1]) for item in self._config.items("InterestingTcpPorts")]
        self._interesting_udp = [("udp_" + item[0], item[1]) for item in self._config.items("InterestingUdpPorts")]
        self._nmap_tcp_scripts = config["NmapScripts"]["tcp"]
        self._nmap_udp_scripts = config["NmapScripts"]["udp"]
        self._nmap_rtt_factor_init = int(config["NmapRttComputation"]["factor_init"])
        self._nmap_rtt_factor_max = int(config["NmapRttComputation"]["factor_max"])
        self._nmap_max_scan_delay = config["NmapRttComputation"]["max_scan_delay"]
        self._nmap_general_options = config["NmapGeneralSettings"]["default_options"]
        self._nmap_tcp_options = config["NmapGeneralSettings"]["tcp_options"]
        self._nmap_udp_options = config["NmapGeneralSettings"]["udp_options"]
        self._masscan_general_options = config["MasscanGeneralSettings"]["default_options"]
        self._avg_rtt = args.avg_rtt
        self._top_udp = args.top_udp
        self._top_tcp = args.top_tcp
        self._dns_server = args.dns_server
        self._args = args
        self._nmap_options_first_run = config["NmapGeneralSettings"]["default_options_first_run"]
        self._nmap_options_not_first_run = config["NmapGeneralSettings"]["default_options_not_first_run"]
        self._first_run = True

        if args.bash and args.bash == "nmap":
            if args.exec_path:
                self._exec = args.exec_path
            else:
                self._exec = config["NmapGeneralSettings"]["exec_linux"]
        elif args.bash and args.bash == "masscan":
            if args.exec_path:
                self._exec = args.exec_path
            else:
                self._exec = config["MasscanGeneralSettings"]["exec_linux"]
        elif args.dos_nmap:
            if args.exec_path:
                self._exec = args.exec_path
            else:
                self._exec = config["NmapGeneralSettings"]["exec_windows"]

    @property
    def _first_run_options(self):
        options = ""
        if self._first_run:
            options = self._nmap_options_first_run
            if self._dns_server:
                options += " --dns-server {}".format(self._dns_server)
            self._first_run = False
        return options

    @property
    def _nmap_options(self):
        rvalue = self._nmap_general_options
        return re.sub("\s+", " ", rvalue)

    def _get_rtt_computation_script(self):
        raise NotImplementedError("Function not implemented in subclass!")

    def _get_init_script_variables(self):
        raise NotImplementedError("Function not implemented in subclass!")

    def _get_pre_script(self):
        raise NotImplementedError("Function not implemented in subclass!")

    def _get_post_script(self):
        raise NotImplementedError("Function not implemented in subclass!")

    def _get_interesting_tcp(self):
        raise NotImplementedError("Function not implemented in subclass!")

    def _get_remaining_tcp(self):
        raise NotImplementedError("Function not implemented in subclass!")

    def _get_interesting_udp(self):
        raise NotImplementedError("Function not implemented in subclass!")

    def _get_top_tcp(self):
        raise NotImplementedError("Function not implemented in subclass!")

    def _get_top_udp(self):
        raise NotImplementedError("Function not implemented in subclass!")

    def get_full_script(self):
        self._first_run = True
        rvalue = self._get_pre_script() + os.linesep
        rvalue += self._get_init_script_variables()
        rvalue += self._get_rtt_computation_script() + os.linesep * 2
        rvalue += self._get_interesting_tcp() + os.linesep
        rvalue += self._get_interesting_udp() + os.linesep
        if self._top_tcp:
            rvalue += self._get_top_tcp() + os.linesep
        else:
            rvalue += self._get_remaining_tcp() + os.linesep
        rvalue += self._get_top_udp() + os.linesep
        rvalue += self._get_post_script()
        return rvalue

    def __repr__(self):
        return self.get_full_script()
