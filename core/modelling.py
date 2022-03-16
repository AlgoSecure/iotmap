from utils.utils import command, cls_commands
from utils.utils import main_help, convert_str_to_array, compare2arrays, packet_loss_file
from utils.generateResults import get_optimal_delta, plot_controller_delta, plot_packet_loss, plot_pbc_theta 
from utils.completer import IMCompleter
from terminaltables import AsciiTable
import csv


from prompt_toolkit.shortcuts import ProgressBar

import subprocess
import ast

from numpy import arange, std, mean

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

        self.dbc.dlGraph(filename=filename)

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
    def appGraph(self, pattern:str, delta: float, filename:str=None):
        """AppGraph
        Generate the network graph of the modelling. If uppers layers have already been generated, this function
        deletes all upper layers. 

        Usage: appGraph [-h] [--pattern <pattern>] [--delta <delta>] [--filename <filename>]

        Options:
            -h, --help               Print this help menu.
            -d, --delta delta        Delta is the delay for a controller to forward a packet [Default: 1.5].
            -f, --filename filename  File with packets at unified format to generate the graph.
            -p, --pattern pattern    Pattern to use to provide the application graph [Default: interact].

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

        self.dbc.appGraph(pattern, delta, tdelta, tdelta2, filename)

    @command
    def listPatterns(self, graph: int):
        """listPatterns
        Display the list of patterns available in IoTMap. Morevoer, the display is organized according to 
        the graph in which the pattern is associated  

        Usage: listPattern [-h] [--graph <graph>]

        Options:
            -h, --help               Print this help menu.
            -g, --graph graph        Dsplay the list of patterns available to a specific graph [Default: 0].
            
        Remarks:
            To select a specific graph and display the patterns available to only this graph, you can choose the
            -g option, where:
                0: all
                1: datalink
                2: network
                3: transport
                4: application
        """

        graphs = ['all', 'datalink', 'network', 'transport', 'application']
        patterns = self.dbc.db._graph_patterns
        
        for g in patterns:
        
            if graph != 0 and g != graphs[graph]:
                continue

            table_data = [
                ["Name", "Description"]
            ]

            for p in patterns[g]:
                table_data.append([p, patterns[g][p]])
            
            table = AsciiTable(table_data)
            table.inner_column_border = False
            table.inner_footing_row_border = False
            table.inner_heading_row_border = True
            table.inner_row_border = False
            table.outer_border = False
            
            print (f'\n{g}:\n\n{table.table}\n')

        #print(f"{self.dbc.db._graph_patterns}")      

    @command
    def compareTo(self, filename:str, dstart:float, dend:float, dstep:float, output:str, ctrl:bool):
        """CompareTo
        Compare the result of the current run of the modelling (with the level you want) and a file 
        that contains expected results.
        This function returns the difference between the expected result and the current run of the modelling

        Usage: compareTo [-h] (--filename <filename>) [-c] (delta <dstart> <dend> <dstep>) 
                         [--output <output>]

        Options:
            -h, --help                 Print this help menu.
            -l, --level level          Set the number of layers of the graph [Default: 4].
            -f, --filename <filename>  Csv File containing expected results to compare with.
            -o, --output <output>      File where results will be stored [Default: tests/results.txt].
            -c, --ctrl                 Option to determine if the we compare the pbc pattern or the ctrl pattern.[Default: False]
            delta                      Value used to determine which node acts as a controller.
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

        with ProgressBar() as pb:
            graphs = {}
            for d in pb(arange(dstart, dend, dstep)):
                if ctrl:
                    pbc, current = self.dbc.transGraph(0.6, d.item(), None)
                    # current = self.dbc.getResults()
                else :
                    current, ctrl = self.dbc.transGraph(d.item(), -1, None)
                
                graphs[d] = current

            # tdelta = get_optimal_delta(retTab.copy(), graphs, plot=True, isT1=True, debug=output)
            if ctrl:
                plot_controller_delta(retTab.copy(), graphs, plot=True, debug=output)
            else:
                plot_pbc_theta(retTab.copy(), graphs, plot=True, debug=output)


    @command
    def packetLossResults(self, compare:str, filename:str, pstart:int, pend:int, pstep:int, repeat:int, output:str):
        """packetLossResults
        This function returns a plot that represents relevance of the modelling according to the rate of packets loss

        Usage: packetLossResults [-h] (--compare <compare>) (--filename <filename>) (percent <pstart> <pend> <pstep>) (--repeat <repeat>) [--output <output>]

        Options:
            -h, --help                   Print this help menu.
            -f, --filename <filename>    Csv File containing the sample for this test
            -c, --compare <compare>      Csv File containing the sample for this test
            -o, --output <output>      File where results will be stored [Default: tests/results-packetLoss.txt].
            -r, --repeat <repeat>        The number of repeat for each step.[Default: 5]
            percent                      Rate of packets loss we consider in the file
        """

        tdelta = self.options['tdelta1']['Current Settings']
        tdelta2 = self.options['tdelta2']['Current Settings']
        adelta = self.options['adelta']['Current Settings']
        with open(filename, 'r') as packetsFile:
            csvData = packetsFile.readlines()

        try:
            with open(compare, 'r') as csvFile:
                toCompare = []
                for line in csvFile.readlines():
                    toCompare.append(line.strip())
        except IOError as ioe:
            print(f"CSVFile: {compare}")
            print(f'Error while opening the file...\n{ioe}')
            return False
        except :
            print(f"CSVFile: {compare}")
            print(f'Error while opening into CSV file...')
            return False

        retTab = convert_str_to_array(toCompare)

        graphs = {}
        for rate in range(pstart, pend, pstep):
            tmp = []
            for r in range(repeat):
                samplePacket = packet_loss_file(csvData, rate)
                self.dbc.dlGraph(packets=samplePacket)
                self.dbc.nwkGraph()
                current = self.dbc.transGraph(tdelta, tdelta2)
                tmp.append(current)
                #self.dbc.appGraph(adelta, tdelta, tdelta2)
            graphs[rate] = tmp
        plot_packet_loss(retTab.copy(), graphs, plot=True, debug=output)


    @command
    def getTimeRouting(self, filename:str, output:str, timestamp:int):
        """getTimeRouting
        This function returns the min, max, average and the standard deviation for each node poviding routing capabilities
        amongst the different network

        Usage: getTimeRouting [-h] (--filename <filename>) (--output <output>) [--timestamp <timestamp>]

        Options:
            -h, --help                   Print this help menu.
            -f, --filename <filename>    Csv File containing the sample for this test
            -o, --output <filename>      Output file to store results
            -t, --timestamp <timestamp>  Max delta between two communications.[Default: 5]
        """

        try:
            with open(filename, 'r') as csvFile:
                csvData = []
                for line in csvFile.readlines():
                    csvData.append(line.strip().split(','))
        except IOError as ioe:
            print(f"CSVFile: {filename}")
            print(f'Error while opening the file...\n{ioe}')
            return False
        except :
            print(f"CSVFile: {filename}")
            print(f'Error while opening into CSV file...')
            return False

        res = {}

        with open(output, 'w') as outputFile:
            for line in csvData:
                protocol = line[0]
                source = int(line[1])
                router = int(line[2])
                dest = int(line[3])

                ret = self.dbc.getRoutingFrames(source, router, dest, timestamp)

                if ret != []:
                    delta = []

                    for l in ret :
                        delta.append(float(l[3]) - float(l[1]))


                    if protocol in res.keys():
                        if router in res[protocol].keys():
                            res[protocol][router] += delta
                        else:
                            res[protocol].update({router: delta})
                    else:
                        res[protocol] = {router: delta}


            for p in res.keys():
                for r in res[p].keys():
                    minimal = min(res[p][r])
                    maximal = max(res[p][r])
                    average = mean(res[p][r])
                    standardDeviation = std(res[p][r])

                    outputFile.write(f"{p} - {r}\n{res[p][r]}\nMin: {minimal}\tMax: {maximal}\nAverage: {average}\tStandardDeviation: {standardDeviation}\n\n")

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
        
