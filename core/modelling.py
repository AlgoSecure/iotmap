from utils.utils import command, cls_commands
from utils.utils import main_help, convert_str_to_array, compare2arrays
from utils.completer import IMCompleter
from terminaltables import AsciiTable
import csv

from prompt_toolkit.shortcuts import ProgressBar

import subprocess
import ast

from numpy import arange

# from scapy.layers.dot15d4 import *
# from scapy.layers.zigbee import *
# from scapy.layers.sixlowpan import *
# from scapy.utils import *

@cls_commands
class Modelling:
    def __init__(self, prompt_session, dbController, options):
        self.name = 'modelling'
        self.description = "Modelling mode."
        self.prompt = 'IoTMap modelling > '
        self.completer = IMCompleter(self)
        self.dbc = dbController
        self.graphs = {}
        self.prompt_session = prompt_session
        
        self.options = {
            'level': {
                'Current Settings': options['level'],
                'Require': False,
                'Description': 'Set the number of layers of the graph [default: 4].',
                'type': int
            },
            #We can add multiple options such as type of application, protocol-based modelling, etc.
            'csvFile': {
                'Current Settings': None,
                'Require': False,
                'Description': 'CSV file containing packets converted into unified format.',
                'type': str
            },
            'tdelta1': {
                'Current Settings': .6,
                'Require': False,
                'Description': 'Delay for an object to respond to a request. This value is used to build the transport graph.',
                'type': float    
            },
            'tdelta2': {
                'Current Settings': .7,
                'Require': False,
                'Description': 'Delay for an object to forward a packet. This value is used to build the transport graph.',
                'type': float
            },
            'adelta': {
                'Current Settings': 1.5,
                'Require': False,
                'Description': 'Delay for a controller to forward a packet. This value is used to build the application graph.',
                'type': float
            }
        }

        
        self.prompt_session = prompt_session

        self.updateGraphOptions()
               
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
            self.options[name]['Current Settings'] = self.options[name]['type'](value)
            self.updateGraphOptions()
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
    def get_current_graph(self, output:str=None):
        """Get current Graph
        Display the current graph with the neo4j format data.

        Usage: get_current_graph [-h] [--output <output>]

        Options:
            -h, --help  Print this help menu
            -o, --output <output>  Output file where the display will be stored.
        """
        current = self.dbc.getResults()
        if not output is None:
            with open(output, 'w') as outputFile:
                for line in current:
                    outputFile.write(f"{str(line)[1:-1]}\n")
        print(f"Current Graph:\n{current}")

    @command
    def run(self):
        """
        Generate a graph based on the traffic intercepted and store in the database. Level number defined in 
        the options indicates the number of layers displayed in this graph. 

        Usage: run [-h]

        Options:
            -h, --help  print this help menu
        """
        
        level = int(self.options["level"]["Current Settings"])
        filename = self.options["csvFile"]["Current Settings"]
        if level == 2 and filename is None:
            print("You want to (re)build the dl graph but no csvFile is provided. You must define a value to csvFile before run level 2 of the modelling")
        else:
            print(self.graphs[level]['options'])
            self.graphs[level]['func'](*self.graphs[level]['options'])
            results = self.dbc.getResults()
            print(f"Actual Results: {results}")
        
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
Modelling commands
==================

        Map the network of IoT devices detected by sniffing.

List of available commands :\n"""

        for x in self._cmd_list:
            msg += f'\t{x}\n'

        msg += f"""
For more information about any commands hit : 
        <command name> -h
        """
        
        print(msg)



    @command
    def dlGraph(self, filename:str=None):
        """DlGraph
        Generate the first graph of the modelling. If uppers layers have already been generated, this function
        deletes all upper layers. 

        Usage: dlGraph [-h] [--filename filename]

        Options:
            -h, --help               Print this help menu
            -f, --filename filename  File with packets at unified format to generate the graph.
        """

        # TODO: make a file checking
        # Check if the file is correctly formed

        self.dbc.dlGraph(filename)

    @command
    def nwkGraph(self, filename:str=None):
        """NwkGraph
        Generate the network graph of the modelling. If uppers layers have already been generated, this function
        deletes all upper layers. 

        Usage: nwkGraph [-h] [--filename filename]

        Options:
            -h, --help               Print this help menu
            -f, --filename filename  File with packets at unified format to generate the graph.
        """

        # TODO: make a file checking
        # Check if the file is correctly formed
        self.dbc.nwkGraph(filename)

    @command
    def transGraph(self, delta: float, delta2: float,  filename:str=None):
        """TransGraph
        Generate the network graph of the modelling. If uppers layers have already been generated, this function
        deletes all upper layers. 

        Usage: transGraph [-h] [--delta <delta1>] [--delta2 <delta2>] [--filename <filename>]

        Options:
            -h, --help               Print this help menu.
            -d, --delta delta1       Delta1 is the delay for an object to respond to a request [Default: 0.6].
            -e, --delta2 delta2      Delta2 is the delay for an object to forward a packet [Default: 0.7].
            -f, --filename filename  File with packets at unified format to generate the graph.
        """

        # TODO: make a file checking
        # Check if the file is correctly formed
        self.dbc.transGraph(delta, delta2, filename)

    @command
    def appGraph(self, delta: float, filename:str=None):
        """AppGraph
        Generate the network graph of the modelling. If uppers layers have already been generated, this function
        deletes all upper layers. 

        Usage: appGraph [-h] [--delta <delta>] [--filename <filename>]

        Options:
            -h, --help               Print this help menu.
            -d, --delta delta        Delta is the delay for a controller to forward a packet [Default: 1.5].
            -f, --filename filename  File with packets at unified format to generate the graph.

        Remarks:
            If you use the --filename options, IoTMap gonna uses the tdelta1 and tdelta2 values defined in 
            options. 
            To display those values use the option command: "IoTMap modelling > option".
            To modify the value, use the set command: "IoTMap modelling > set <name> <value>".
        """

        # TODO: make a file checking
        # Check if the file is correctly formed
        tdelta = self.options['tdelta1']['Current Settings']
        tdelta2 = self.options['tdelta2']['Current Settings']
        self.dbc.appGraph(delta, tdelta, tdelta2, filename)

    @command
    def compareTo(self, filename:str, td1start:float, td1end:float, td1step:float,
                  td2start:float, td2end:float, td2step:float, adstart:float, adend:float,
                  adstep:float, output:str, level:int=4):
        """CompareTo
        Compare the result of the current run of the modelling (with the level you want) and a file 
        that contains expected results.
        This function returns the difference between the expected result and the current run of the modelling

        Usage: compareTo [-h] (--filename <filename>) [--level <level>] (tdelta1 <td1start> <td1end> <td1step>) 
                         (tdelta2 <td2start> <td2end> <td2step>) (adelta <adstart> <adend> <adstep>) [--output <output>]

        Options:
            -h, --help                 Print this help menu.
            -l, --level level          Set the number of layers of the graph [Default: 4].
            -f, --filename <filename>  Csv File containing expected results to compare with.
            -o, --output <output>      File where results will be stored [Default: results.txt].
            tdelta1                    Options relating to the first delta of the transport graph.
            tdelta2                    Options relating to the second delta of the transport graph.
            adelta                     Options relating to the delta of the application graph.
        """
        try:
            with open(filename, 'r') as csvFile:
                csvData = []
                for line in csvFile.readlines():
                    csvData.append(line.strip())
        except IOError as ioe:
            print(f"CSVFile: {filename}")
            print(f'Error while opening the file...\n{ioe}')
            return False
        except :
            print(f"CSVFile: {filename}")
            print(f'Error while opening into CSV file...')
            return False

        retTab = convert_str_to_array(csvData)

        with open(output, 'w') as outputFile:
            outputFile.write(f"Expected Results: {retTab}")

        with ProgressBar() as pb:
            for t1 in pb(arange(td1start, td1end, td1step)):
                for t2 in arange(td2start, td2end, td2step):
                    for a in arange(adstart, adend, adstep):
                        self.transGraph(t1, t2)
                        self.appGraph(a)

                        current = self.dbc.getResults()

                        missing, extra = compare2arrays(retTab, current)
                        with open(output, 'a') as outputFile:
                            outputFile.write(f"\n\nTdelta1: {t1}\tTdelta2: {t2}\tAdelta: {a}")
                            outputFile.write(f"\nCurrent: {current}\n\nMissings: {missing}\n\nExtra: {extra}")
        
        # Now we gonna extract the difference between the expected result and the current one
        # We must display missing and extra elements compare to the expected result
        #print(f"ER - C: {res}")
        #print(f"C: {set(current) - set(retTab)}")

    def updateGraphOptions(self):
        self.graphs = {
            1: {
                'func': self.dbc.dlGraph,
                'options': [self.options["csvFile"]['Current Settings']]
            },
            2: {
                'func': self.dbc.nwkGraph,
                'options': [self.options["csvFile"]['Current Settings']]
            },
            3: {
                'func': self.dbc.transGraph,
                'options': [self.options["tdelta1"]['Current Settings'],
                            self.options["tdelta2"]['Current Settings'],
                            self.options["csvFile"]['Current Settings']]
            },
            4: {
                'func': self.dbc.appGraph,
                'options': [self.options["adelta"]['Current Settings'],
                            self.options["tdelta1"]['Current Settings'],
                            self.options["tdelta2"]['Current Settings'],
                            self.options["csvFile"]['Current Settings']]
            }
        }
        
