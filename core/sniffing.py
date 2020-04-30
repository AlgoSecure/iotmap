from utils.utils import command, cls_commands
from utils.utils import main_help
from utils.completer import IMCompleter
from terminaltables import AsciiTable

import subprocess
import ast

from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *
from scapy.layers.sixlowpan import *
from scapy.utils import *

@cls_commands
class Sniffing:
    def __init__(self, prompt_session, dbController, options):
        self.name = 'sniffing'
        self.description = "Live sniffing mode."
        self.prompt = 'IoTMap sniffing > '
        self.completer = IMCompleter(self)
        
        self.prompt_session = prompt_session
        
        self.options = {
            'channel': {
                'Current Settings': options['channel'],
                'Require': False,
                'Description': 'Channel to sniff [default: 15].'
            },
            'timeout': {
                'Current Settings': options['timeout'],
                'Require': False,
                'Description': 'Numbers of second to sniff [default: 15].'
            },
            'packetNb': {
                'Current Settings': options['packetNb'],
                'Require': False,
                'Description': 'Numbers of packets to sniff [default: 100].'
            },
            'protocol': {
                'Current Settings': options['protocol'],
                'Require': True,
                'Description': 'Treat layer 3 as the protocol "Protocol"'
            },
            'output': {
                'Current Settings': options['output'],
                'Require': False,
                'Description': 'Output file to store the result of the sniffing'
            },
            'nbthread': {
                'Current Settings': options['nbthread'],
                'Require': False,
                'Description': 'Number of threads allocated to process the analysis of the communications intercepted.'
            }
        }

        self.dc = dbController
        
    @command
    def set(self, name: str, value: str):
        """
        Set an option to the value 'value'        

        Usage: set <name> <value> [-h]

        Options:
            -h, --help  print this help menu

        Arguments:
            name   option name
            value  option value
        """

        try:
            self.options[name]['Current Settings'] = value
            print (f"{name} set to {value}")
        except KeyError:
            print(f"Unknown option '{name}'")

    @command
    def option(self):
        """
        Print the options required by the module

        Usage: options [-h]

        Options:
            -h, --help  print this help menu
        """
            
        table_data = [
            ["Name", "Current Settings", "Required", "Description"]
        ]
        
        for name, options in self.options.items():
            table_data.append([name, options["Current Settings"], options["Require"], options["Description"]])
            
        table = AsciiTable(table_data)
        table.inner_column_border = False
        table.inner_footing_row_border = False
        table.inner_heading_row_border = True
        table.inner_row_border = False
        table.outer_border = False
        
        print (f'\nModule Options ({self.name}):\n\n{table.table}\n')
            

    @command
    def run(self):
        """
        Run the sniffing with the the current settings and update the database 
        with the news packets

        Usage: run [-h]

        Options:
            -h, --help             Print this help menu.
        """
        
        channel = self.options["channel"]["Current Settings"]
        timeout = self.options["timeout"]["Current Settings"]
        packetnb = self.options["packetNb"]["Current Settings"]
        protocol = self.options["protocol"]["Current Settings"]
        output = self.options["output"]["Current Settings"]
        nbthread = self.options["nbthread"]["Current Settings"] 
        
        filename = './pcap/live-sniff.pcap'

        command = f'sudo python2 ./sniffer/get_packets.py -c {channel} -t {timeout} -p {packetnb} -f {filename}'
        
        print("Start sniffing")
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
        output, error = process.communicate()
        print(f"End of sniffing\n{output.decode('utf8').strip()} packets read")

        try:
            #pkts = rdpcap(filename)
            pcaps = {
                'zigbee': filename,
            }
            
            ret = self.dc.update(pcaps, output, nbthread)
        except FileNotFoundError:
            print("File not found")

        # If ret is False then something wrong happened
        if not ret:
            print(f"Something wrong happened during the csv writting")
            

        
    @command
    def help(self):
        """
        Print this help menu 

        Usage: help
        """        
        # Print the global commands
        # and the context-aware commands
        msg = main_help()

        msg += f"""
Sniffing commands
=================

        Map the network of IoT devices detected by sniffing.

List of available commands :\n"""

        for x in self._cmd_list:
            msg += f'\t{x}\n'

        msg += f"""
For more information about any commands hit : 
        <command name> -h
        """
        
        print(msg)

