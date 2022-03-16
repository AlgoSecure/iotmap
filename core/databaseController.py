import time
import sys
import csv
import subprocess
import logging
import functools
from utils.utils import readNodesFile 
from utils.buildNode import createNode
from database.nodesdatabase import NodesDatabase
from neo4j import GraphDatabase
from shlex import split
from docopt import docopt, DocoptExit

from sniffer.gen_packet import gen_packet, genPacketSort


class DBController(object):
    def __init__(self):
        self.db = NodesDatabase("bolt:http://localhost:7687", "neo4j", "iotmap") # or port 7474

    # Return a dictionnary of TX transmissions
    def loadCSV(self, csvfile):
        nodeTX = {}
        i = 0
        # If file type is str then it is a file to open
        # if it is a list type, then the csvfile is directly gave as args
        for line in csvfile:
            try:
                protocol, t, dls, dld, nwks, nwkd, appt, p = line
            except:
                logging.debug(f"An error occurs, something's wrong with the csv file {csvfile} ")
                return None
            
            nodeTX[f'nodeTX{i}'] = self.setTxProperties(protocol, float(t), dls, dld, nwks, nwkd, int(appt), p)
            i += 1

        #return nodeTX, nodes
        return nodeTX

    # This function takes array of nodes in parameters
    # Define the right properties of each node of the array
    # Import the result into the database
    def importNodes(self, listNodes):
        nodes = []
        i = 0
        for node in listNodes:  
            nameID, dlsrc, nwksrc = node
            nodes.append([nameID, dlsrc, nwksrc, 2, []])
            i += 1

        self.db.create_nodes(nodes)
    

    def setTxProperties(self, protocol, timestamp, dlsrc, dldst, nwksrc, nwkdst, apptype, data):
        properties = {
            "protocol": protocol,     # Protocol used to communicate 
            "timestamp": timestamp,
            "dlsrc": dlsrc,           # Data link src address
            "dldst": dldst,           # Data link dst address
            # Network layer
            "nwksrc": nwksrc,         # Nwk src address
            "nwkdst": nwkdst,         # Nwk dst address
            # transport layer
            "apptype": apptype,       # Id of the cluster
            # Application layer
            "data": data
        }

        return properties


    # Called by the import_pcap function in the module Database
    # It consists of converting protocol-based pcap to a single
    # file with a unified format
    # Then use the result to create the nodes and the transmission
    # TODO: Currently the nodes properties are hardcoded but a function will
    # come to extract each address from the pcap and provide the set of nodes
    def update(self, pcaps_list, output, nbThread, nodesFile):
        csvData = []
        for protocol in pcaps_list.keys():
            for pcap in pcaps_list[protocol]:
                csvData += gen_packet(pcap, protocol.upper(), nbThread, True)

        # Let order the list by timestamp
        csvData.sort(key=lambda x: x[1])

        csvData = genPacketSort(csvData)

        try:
            logging.info(f"[i] Writting into {output} file")
            with open(output, 'w') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerows(csvData)
            
            logging.info(f"[i] Result wrote in {output}")
        except IOError as ioe:
            #print(f"CSVFile: {csvData}")
            logging.error(f'Error while opening the file...\n{ioe}')
            return False
        except csv.Error as csve:
            #print(f"CSVFile: {csvData}")
            logging.error(f'Error while writting into CSV file...\n{csve}')
            return False
        except :
            #print(f"CSVFile: {csvData}")
            logging.error(f'Error while writting into CSV file...')
            return False

        if nodesFile is None:
            nodes = self.extractNodes(csvData)
            self.db.create_nodes(nodes)
        else:
            nodes = readNodesFile(nodesFile)
            self.importNodes(nodes)          
            
        nodesTx = self.loadCSV(csvData)
        self.db.create_nodesTX(nodesTx)
        return True


    # This function builds the first graph only (data link graph or point-to-point communications)
    def dlGraph(self, filename=None, packets=None):
        # If filename is provided then we erase the database and
        # use the content of the file as data
        print(f'{filename}')
        if filename is not None or packets is not None:
            self.delNodes(3, 'node')
            self.delNodes(2, 'visu')
            self.db.removeTX(2)

            if filename :
                with open(filename, 'r') as csvFile:
                    csvData = list(csv.reader(csvFile, delimiter=','))

                nodesTx = self.loadCSV(csvData)
            else :
                nodesTx = self.loadCSV(packets)
                #self.db.create_nodes(nodes)

            self.db.create_nodesTX(nodesTx)

            return True
        # Check if transmissions are not already stored in the database
        else:
            return None

    # This function builds the network graph (end-to-end communications)
    # Build the dlGraph if it does not exist
    def nwkGraph(self, filename=None):
        # If filename is provided then we erase the database and
        # use the content of the file as data
        if filename is not None:
            self.dlGraph(filename)
        # Check if nwk transmissions are not already stored in the database
        else:
            self.delNodes(3, 'node')
            self.delNodes(3, 'visu')
            
        self.db.nwkGraph()


    # This function builds the transport graph (Role of the nodes in the network)
    # Build the dlGraph and the nwkGraph if they do not exist
    def transGraph(self, pattern, delta, delta2, filename=None):
        # If filename is provided then we erase the database and
        # use the content of the file as data
        if filename is not None:
            self.nwkGraph(filename)
        # Check if trans transmissions are not already stored in the database
        else:
            self.delNodes(4, 'node')
            
        if delta2 is not None and delta2 < 0.:
            delta2 = None

        ret = self.db.transGraph(pattern, delta, delta2)
        return ret

    # This function builds the application graph (Currently only Interaction pattern)
    # Build the 3 previous graphs if they do not exist
    def appGraph(self, pattern, delta, tdelta1, tdelta2, filename=None):
        # If filename is provided then we erase the database and
        # use the content of the file as data
        if filename is not None:
            self.transGraph('transport_transmission', tdelta1, tdelta2, filename)
        # Check if trans transmissions are not already stored in the database
        else:
            self.delNodes(5, 'node')
            
        self.db.appGraph(pattern, delta)

        
    def delNodes(self, label, mode):
        self.db.del_nodes(label, mode)

    def getResults(self):
        return self.db.getResults()

    # Extract and list potential nodes found in 
    # the file of transmissions
    # csvData is an array containing transmission information
    # We use a protocol-specific function to create a node based on its dl address
    def extractNodes(self, csvData):
        nodes = []
        for line in csvData:
            protocol, dlsrc, dldst = line[0], line[2], line[3]
            n1 = createNode(protocol, dlsrc)
            n2 = createNode(protocol, dldst)
            if n1 not in nodes:
                nodes.append(n1)
            if n2 not in nodes:
                nodes.append(n2)
        nodesTocreate = []
        i = 1
        for n in nodes:
            nodesTocreate.append([i, n[0], n[1], 2, []])
            i+=1

        return nodesTocreate

    # Get all nodes already stored in the database
    def getNodes(self):
        nodes = self.db.getNodes()

        return nodes

    def getNode(self, nodeID):
        node = self.db.getNode(nodeID)

        return node

    def maxID(self):
        return self.db.maxID()

    def removeNode(self, nodeID):
        ret = self.db.removeNode(nodeID)

        return ret


    def getRoutingFrames(self, source, router, dest, delta):
        return self.db.getRoutingFrames(source, router, dest, delta)
