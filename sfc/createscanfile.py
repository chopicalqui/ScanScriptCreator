#!/usr/bin/python3

"""
This Python script implements the commandline interface to create Nmap and Masscan scan scripts.
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

import argparse
import configparser
import os
import sys
from lib import bash
from lib import dos

parser = argparse.ArgumentParser()
parser.add_argument("--bash", help="create bash script for nmap or masscan", type=str)
parser.add_argument("--dos-nmap", help="print nmap scan script for dos", action="store_true")
parser.add_argument("-i", "--interface", help="specify network interface for masscan", type=str)
parser.add_argument("--exclude", nargs="*", type=str, help="exclude host/network. note that in contrast to nmap, "
                                                           "masscan only supports one network range/IP address."
                    , metavar="host")
parser.add_argument("--dns-server", help="specify DNS server that should be used by nmap", type=str)
parser.add_argument("--top-tcp", help="specify number of top TCP ports to scan (default all)", type=int)
parser.add_argument("--top-udp", default=100, help="specify number of top UDP ports to scan (default 100)", type=int)
parser.add_argument("--avg-rtt", default=None, help="specify average round trip time to target network in milliseconds",
                    type=float)
parser.add_argument("--exec-path", help="specify path to nmap/masscan executable", type=str)
args = parser.parse_args()

config_file = os.path.join(os.path.dirname(__file__), "createscanfile.config")
if not os.path.exists(config_file):
    raise FileNotFoundError("Cmdlet config '{}' not found.".format(config_file))
config = configparser.ConfigParser()
config.read(config_file)

if __name__ == "__main__":
    script_creator = None
    if args.bash and args.bash not in ["nmap", "masscan"]:
        print("Argument for option --bash must be either 'nmap' or 'masscan'.", file=sys.stderr)
        sys.exit(1)
    if args.bash and args.bash == "nmap":
        script_creator = bash.NmapScriptCreator(config, args)
    elif args.bash and args.bash == "masscan":
        if not args.interface:
            print("If you use masscan, please specify an network interface over which you want to scan.",
                  file=sys.stderr)
            sys.exit(1)
        script_creator = bash.MasscanScriptCreator(config, args)
    elif args.dos_nmap:
        script_creator = dos.NmapScriptCreator(config, args)
    if script_creator:
        print(script_creator)
    else:
        print("Error: No operating system specified; exiting application.{}".format(os.linesep), file=sys.stderr)
        parser.print_help()
        sys.exit(1)
