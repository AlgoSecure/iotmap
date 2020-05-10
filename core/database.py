from utils.utils import command, cls_commands, readNodesFile
from utils.utils import check_protocol, unify_pcaps
from utils.utils import main_help, formatArray
from utils.completer import IMCompleter
from terminaltables import AsciiTable

from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *
from scapy.layers.sixlowpan import *
from scapy.utils import *

import subprocess
import os

@cls_commands
class Database:
    def __init__(self, prompt_session, dbController):
        self.name = 'database'
        self.description = "Database mode."
        self.prompt = f'IoTMap database > '
        self.completer = IMCompleter(self)

        self.prompt_session = prompt_session
        self.dbc = dbController
        
    @command
    def importPcaps(self, pcap: list, protocol: list, output: str, thread: int, nodesFile: str=None):
        """
        Import the pcap file into the database

        Usage: importPcaps (<protocol> <pcap>)... [--output <filename>] [--thread <nbThread>] [--nodesFile <nodesFile>] 

        Options:
            -h, --help                   Print this message.
            -o, --output <filename>      Output file to store the result.
            -t, --thread <nbThread>      Thread number to use [default: 1].
            -n, --nodesFile <nodesFile>  File that contains a list of nodes used in communications. 
        
        Arguments:
            protocol                   Name of the IoT protocol. 
            pcap                       Pcap file from the specific protocol defined in the previous arg.
        
        Examples:
            import_pcap zigbee file1.pcap zigbee file2.pcap os4i file3.pcap --thread 2 -o zigbee-os4i.csv
            import_pcap btle file1.pcap os4i file3.pcap -t 2 -o btle-os4i.csv
            import_pcap os4i file.pcap --thread 3 --debug --output os4i.csv
        """
        print(f"[i] Pcaps: {pcap}\nProtocols: {protocol}\nOutput: {output}\nThread: {thread}")
        if check_protocol(protocol):
            try:
                pcaps_list = unify_pcaps(protocol, pcap)
                print(f"[i] Pcaps_list: {pcaps_list}\nOutput: {output}\nThread: {thread}")
                self.dbc.update(pcaps_list, output, thread, nodesFile)

            except FileNotFoundError:
                print("File not found")
        else:
            print(f"{protocol} is not a protocol available")
            

    @command
    def importDB(self, dump_db: str):
        """
        Import a neo4j dump into the database 

        Usage: loadDB <dump_db> [-h]

        Options:
            -h, --help  print this help menu

        Arguments:
            dumb_db    absolute path to the dump file
        """

        # TODO: Add a new test to check if the file given in input is
        # a good dump file for neo4j
        if not os.path.isfile(dump_db):
            error = f'The {dump_db} file does not exist.'
            print(error)

            return
        
        neo4j = "./database/neo4j-community/bin/neo4j"
        neo4j_admin = "./database/neo4j-community/bin/neo4j-admin"

        process = subprocess.Popen(f"{neo4j} stop", shell=True, stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE)
        output, error = process.communicate()
        
        process = subprocess.Popen(f"{neo4j_admin} load  --from={dump_db} --database=graph.db", 
                                   shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        
        # TODO : Test if no error occured
        
        # Restart the server
        process = subprocess.Popen(f"{neo4j} start", shell=True, stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE)
        output, error = process.communicate()
        
    @command
    def exportDB(self, path: str):
        """
        Export the content of the database to 'path'

        Usage: exportDB <path> [-h]

        Options:
            -h, --help  print this help menu

        Arguments:
            path  abolute path where to export the database 
        """
        
        # The only way is to stop the neo4j server, dump the base
        # and restart the server       
        neo4j = "./database/neo4j-community/bin/neo4j"
        neo4j_admin = "./database/neo4j-community/bin/neo4j-admin"

        process = subprocess.Popen(f"{neo4j} stop", shell=True, stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE)
        output, error = process.communicate()
        
        process = subprocess.Popen(f"{neo4j_admin} dump --database=graph.db --to={path}", shell=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        
        # TODO : Test if no error occured
        
        # Restart the server
        process = subprocess.Popen(f"{neo4j} start", shell=True, stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE)
        output, error = process.communicate()
        
    @command
    def clearDatabase(self):
        """
        Erase the whole database

        Usage: clearDatabase [-h]

        Options:
            -h, --help  print this help menu
        """

        self.dbc.delNodes(2, 'node')
        self.dbc.delNodes(2, 'visu')    

    @command
    def removeNode(self, nodeID:int):
        """
        Remove the node with nodeID from the database

        Usage: removeNode --nodeID <nodeID> 

        Options:
            -h, --help             Print this message.
            -i, --nodeID <nodeID>  ID of the node to remove.
        """

        ret = self.dbc.removeNode(nodeID)

        print(ret)

    # List all nodes stored in the database
    @command
    def getNodes(self):
        """
        List the nodes stored in the database

        Usage: getNodes [-h]

        Options:
            -h, --help             Print this message.
        """

        nodes = self.dbc.getNodes()

        table_data = [["id", "dl addresses", "nwk addresses"]]
        for node in nodes:
            table_data.append(node)
            
        table = AsciiTable(table_data)
        table.inner_column_border = False
        table.inner_footing_row_border = False
        table.inner_heading_row_border = True
        table.inner_row_border = False
        table.outer_border = False
        
        print(f"{table.table}")

    # Merge two nodes together
    @command
    def mergeNodes(self, node1:int, node2:int):
        """
        Merge the dl and nwk addresses of two nodes into a single one

        Usage: mergeNodes --node1 <node1> --node2 <node2>

        Options:
            -h, --help       Print this message.
            --node1 <node1>  The first node to merge.
            --node2 <node2>  The second node to merge.      
        Remarks:
            node{1,2} correspond to the id of the node. This id can be obtained
            with the command listNode
        """

        n1 = self.dbc.getNode(node1)
        n2 = self.dbc.getNode(node2)

        if n1 == [] or n2 == []:
            print("IDs given in arguments don't correspond to a node")
            return

        maxID = self.dbc.maxID()

        node = [maxID[0] + 1]
        for i in range(1, len(n1)):
            if type(n1[i]) is list:
                node.append(list(set(n1[i] + n2[i])))


        self.dbc.import_nodes(node)

        return

    # TODO : The must will be to add a sub content node to manage this.
    @command
    def addNodes(self, filename:str=None, dl:str=None, nwk:str=None, id:int=None):
        """
        Import a list of nodes into the db

        Usage: addNodes (--filename <filename> | --dl <dl> --nwk <nwk> --id <id>)

        Options:
            -h, --help                 Print this message.
            -f, --filename <filename>  File containing the list of nodes with their DL and NWK addresses.
            -d, --dl <dl>              Data link addresses of the node.
            -n, --nwk <nwk>            Network addresses of the node. 
            -i, --id <id>              An identifier for the node.
        
        Remarks:
        The file format must follow this example:
        ID node, dl addresses, nwk addresses
        In the case of multiple addresses for DL and/or NWK addresses, let's separate them with 
        a ';' (semicolon)
        addNode -d aaa:bbb:cccc;1.2.3.4 -n ddd:eee:fff;5.6.7.8 -i 1
        """
        nodes = []

        if filename is not None:
            nodes = readNodesFile(filename)

        else:
            nodes.append([id, dl, nwk])

        self.dbc.importNodes(nodes)
    
    @command
    def help(self):
        """
        Print this help menu 

        Usage: help
        """        
        msg = main_help()

        msg += f"""
Database commands
=================

        Interact with the neo4j database.

List of available commands :\n"""

        for x in self._cmd_list:
            msg += f'\t{x}\n'

        msg += f"""
For more information about any commands hit : 
        <command name> -h
        """
        
        print(msg)
