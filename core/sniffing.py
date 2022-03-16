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

from threading import Thread, Lock
from signal import SIGINT, signal
from sniffer.sixlowpanSniffer import sixlowpanSniffer
from sniffer.bleSniffer import bleSniffer
from sniffer.zigbeeSniffer import zigbeeSniffer

getSniffers = {
    'zigbee': zigbeeSniffer,
    'os4i': sixlowpanSniffer,
    'btle': bleSniffer
}

@cls_commands
class Sniffing:
    def __init__(self, prompt_session, dbController, options):
        self.name = 'sniffing'
        self.description = "Live sniffing mode."
        self.prompt = 'IoTMap sniffing > '
        self.completer = IMCompleter(self)
        self.exit = False
        self.prompt_session = prompt_session
        
        # self.options = {
        #     'channel': {
        #         'Current Settings': options['channel'],
        #         'Require': False,
        #         'Description': 'Channel to sniff [default: 15].'
        #     },
        #     'timeout': {
        #         'Current Settings': options['timeout'],
        #         'Require': False,
        #         'Description': 'Numbers of second to sniff [default: 15].'
        #     },
        #     'packetNb': {
        #         'Current Settings': options['packetNb'],
        #         'Require': False,
        #         'Description': 'Numbers of packets to sniff [default: 100].'
        #     },
        #     'protocol': {
        #         'Current Settings': options['protocol'],
        #         'Require': True,
        #         'Description': 'Treat layer 3 as the protocol "Protocol"'
        #     },
        #     'output': {
        #         'Current Settings': options['output'],
        #         'Require': False,
        #         'Description': 'Output file to store the result of the sniffing'
        #     },
        #     'nbthread': {
        #         'Current Settings': options['nbthread'],
        #         'Require': False,
        #         'Description': 'Number of threads allocated to process the analysis of the communications intercepted.'
        #     }
        # }

        self.sniffers = {}

        self.dc = dbController
        
    # @command
    # def set(self, name: str, value: str):
    #     """
    #     Set an option to the value 'value'        

    #     Usage: set <name> <value> [-h]

    #     Options:
    #         -h, --help  print this help menu

    #     Arguments:
    #         name   option name
    #         value  option value
    #     """

    #     try:
    #         self.options[name]['Current Settings'] = value
    #         print (f"{name} set to {value}")
    #     except KeyError:
    #         print(f"Unknown option '{name}'")

    # @command
    # def options(self):
    #     """
    #     Print the options required by the module

    #     Usage: options [-h]

    #     Options:
    #         -h, --help  print this help menu
    #     """
            
    #     table_data = [
    #         ["Name", "Current Settings", "Required", "Description"]
    #     ]
        
    #     for name, options in self.options.items():
    #         table_data.append([name, options["Current Settings"], options["Require"], options["Description"]])
            
    #     table = AsciiTable(table_data)
    #     table.inner_column_border = False
    #     table.inner_footing_row_border = False
    #     table.inner_heading_row_border = True
    #     table.inner_row_border = False
    #     table.outer_border = False
        
    #     print (f'\nModule Options ({self.name}):\n\n{table.table}\n')
    
    @command
    def addSniffer(self, identifier: int, protocol: str, device: list, name: str=None, channel:int=None, packetNb:int=None, connreq:str=None):
        """
        Add a sniffer to IoTMap

        Usage: addSnifer (--identifier <id>) [--name <name>] (--protocol <protocol>) (--device <device>)... (--channel <channel> | --connreq <connreq>) [--packetNb <packetNb>] [-h]

        Options:
            -h, --help  print this help menu
            -p, --protocol <protocol>  Define the type of sniffer
            -n, --name <name>          Name of the sniffer
            -i, --identifier <id>      Unique identifier to identify the sniffer
            -d, --device <device>      Device to use to process the sniffing. Several devices can be setup
            -c, --channel <channel>    Channel on which the sniffer will listen. This option is protocol-specific
            -a, --connreq <connreq>    BLE specific option - Device address to focus on
            -t, --packetNb <packetNb>  Number of packets to listen
            
        Remarks:
        In the case of BLE, the channel corresponds to the access address.
        
        Examples:
        addSniffer --identifier 1 --protocol os4i --device /dev/ttyACM0 --channel 25
        addSniffer --identifier 1 --protocol zigbee --device 1:5 --channel 25 -t 1500
        addSniffer --identifier 1 --protocol btle --device /dev/ttyACM0 --device /dev/ttyACM1 --channel 0xbb94dbbd
        addSniffer --identifier 1 --protocol btle --device /dev/ttyACM0 --device /dev/ttyACM1 --connreq E0:14:9E:14:11:72
        """  

        if identifier in self.sniffers.keys():
            print(f"[e] The choosen identifier is already used. Please use another identifier for this sniffer.")
            return

        if not protocol in getSniffers.keys():
            print(f"[w] The protocol '{protocol}' is not supported")
            return

        if protocol == 'btle':
            opt = 'sniff'
            if channel is None:
                channel = connreq
                opt = 'connreq'

            options = [name, device, packetNb, channel, opt]    

        else:
            options = [name, device, packetNb, channel]




        sniffer = getSniffers[protocol](options)


        self.sniffers[identifier] = {
            'name': sniffer.name,
            'protocol': protocol,
            'device': device,
            'packetNb': packetNb,
            'channel': channel,
            'opt': options,
            'thread': sniffer
        }

        print(f"[i] Sniffer saved !")



    @command
    def listSniffers(self):
        """
        List avaialble sniffer

        Usage: listSniffers
        """        

        table_data = [
            ["Idenfifier", "Name", "device(s)", "Protocol", "Is_alive"]
        ]

        for s in self.sniffers.keys():
            table_data.append([s, self.sniffers[s]['name'], self.sniffers[s]['thread'].device, self.sniffers[s]['protocol'], self.sniffers[s]['thread'].is_alive()])
            
        table = AsciiTable(table_data)
        table.inner_column_border = False
        table.inner_footing_row_border = False
        table.inner_heading_row_border = True
        table.inner_row_border = False
        table.outer_border = False
        
        print (f'\nList of available sniffers:\n\n{table.table}\n')

    @command
    def run(self, identifier: list):
        """
        Launch defined sniffers to start the traffic capture

        Usage: run [--identifier <identifier>]... [-h]

        Options:
            -h, --help                     Print this help menu.
            -i, --identifier <identifier>  Id of sniffer(s) to start. 
        """
        for s in self.sniffers.keys():
            if len(identifier) != 0:
                if not str(s) in identifier:
                    continue

            if not self.sniffers[s]['thread'].is_alive():
                self.sniffers[s]['thread'].start()
                print(f"[i] Sniffer with the id {s} and the name {self.sniffers[s]['name']} is started")

                
        return 


    @command
    def stopSniffer(self, identifier: list):
        """
        Stop active sniffer

        Usage: stopSniffer [--identifier <identifier>]... [-h]

        Options:
            -h, --help                     Print this help menu.
            -i, --identifier <identifier>  Id of the sniffer to start. 
        """

        for s in self.sniffers.keys():
            if len(identifier) != 0:
                if not str(s) in identifier:
                    continue

            if self.sniffers[s]['thread'].is_alive():
                self.sniffers[s]['thread'].terminate()
                self.sniffers[s]['thread'].join()
                print(f"[i] Sniffer with the id {s} and the name {self.sniffers[s]['name']} is stopped")
                self.sniffers[s]['thread'] = getSniffers[self.sniffers[s]['protocol']](self.sniffers[s]['opt'])
            else:
                print("Sniffer is not active...")
                
        return 
    
    @command 
    def removeSniffer(self, identifier: list):
        """
        Remove sniffer from the list of sniffers

        Usage: removeSniffer (--identifier <identifier>)... [-h]

        Options:
            -h, --help                     Print this help menu.
            -i, --identifier <identifier>  Id of the sniffer to start. 
        """
        todel = []
        for s in self.sniffers.keys():
            if not str(s) in identifier:
                continue

            if self.sniffers[s]['thread'].is_alive():
                print("Sniffer is active, let's stop it before deletion")
                self.sniffers[s]['thread'].terminate()
                self.sniffers[s]['thread'].join()

            print(f"[i] Sniffer with the id {s} and the name {self.sniffers[s]['name']} is removed")
            todel.append(s)
        
        for s in todel:
            del self.sniffers[s]
        
        return 
        
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

        Used defined sniffers to intercept IoT networks.

List of available commands :\n"""

        for x in self._cmd_list:
            msg += f'\t{x}\n'

        msg += f"""
For more information about any commands hit : 
        <command name> -h
        """
        
        print(msg)
