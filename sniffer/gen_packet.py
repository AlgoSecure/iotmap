# from extractors import btleextractor, zigbeeextractor, sixlowpanextractor
# from extractors import btleextractor, zigbeeextractor
from .extractors import btleextractor
from .extractors import bleConstants as bleConstants
from multiprocessing import Pool
import logging
import csv
from scapy.utils import bytes_encode, rdpcap
from scapy.layers.dot15d4 import conf

apptype = {
    'control': 1,
    'ack': 2,
    'command': 3,
    'data': 4,
    'unknown': 5 # Encrypted packets
}

gpkts = []

#extractor = zigbeeextractor.ZigbeeExtractor(key_net, True, 1)
#conf.dot15d4_protocol="zigbee"

def genPacketSort(genPacket):
    '''
    This function sorts the list of generic packet to keep only packets that will be used 
    during the modelling process. We exclude packets without application type, meaning that they don't have 
    application layer, we also exclude packets sent to control or manage the network, that we caracterize 
    with the application type control or ack
    '''
    data = []
    for row in genPacket:
        #logging.debug(f"Row: {row}")
        protocol, t, dls, dld, nwks, nwkd, appt, p = row
        if appt == 3 or appt == 4 or appt == 5:
            # We also exclude broadcast addresses
            if nwkd != '0xffff' and nwkd != '0xfffc' and nwkd != '0xfffd':
                data.append([protocol, t, dls, dld, nwks, nwkd, appt, p])

    return data



class PacketGenerator():
    def __init__(self, protocol, pkts_size, nbThread, verbose):
        self.protocol = protocol
        self.pkts_size = pkts_size
        self.verbose = verbose
        self.nbThread = nbThread
        self.BTLEAddr = {
            'Slave': 'Slave',
            'Master': 'Master'
        }

        # List of supported protocols
        self.protocols = {
            'ZIGBEE': self.ZigBeeConversion,
            'BTLE': self.BTLEConversion,
            'OS4I': self.SixLowPANConversion
        }

        # list of extractors
        self.extractors = {
            'BTLE': {
                'extractor': btleextractor.BTLEextractor,
                'args': [self.verbose]
            },
        }

        if self.protocol == 'ZIGBEE':
            from .extractors import zigbeeextractor
            self.extractors['ZIGBEE'] = {
                'extractor': zigbeeextractor.ZigbeeExtractor,
                'args': [None, True, self.verbose]
                #'args': [None, False, self.verbose]
            }

        elif self.protocol == 'OS4I':
            from .extractors import sixlowpanextractor
            self.extractors['OS4I'] = {
                'extractor': sixlowpanextractor.SixLowPANExtractor,
                'args': [self.verbose]
            }

        # Set the extractor and the function to use
        e = self.extractors[protocol]['extractor']
        self.extractor = e(self.extractors[protocol]['args'])
        self.function = self.protocols[protocol]

    def convertPackets(self):
        logging.info(f'{self.pkts_size} packets will be processed')
        with Pool(int(self.nbThread)) as p:
        # Rather than set as parameter the packets array
        # We set an array of index, and we access the array through a global variable
        # It's a weird way to do it, however it's works
            rows = p.map(self.function, [i for i in range(0, self.pkts_size)])
            
        return rows

    def SixLowPANConversion(self, pkt):
        """Return a row with the unified format if the packet (input) meets all the requirements  
        
        Extracts information from 6LowPAN packet, analyzes it and converts it to the unified format
        if it corresponds to a data packet with specific information.
        """
        # This is the little dirty trick
        # We access to the global variable to get the packet
        packet = gpkts[pkt]
        row = []

        row.append('os4i')
        
        # Print debug
        logging.debug(f"Packet[{pkt}] processed")

        e = self.extractor.extract_pkt_layers(packet)
        logging.debug(f"Packet[{pkt}] extracted: {e}")

        if e is None:
            return None
        
        row.append(e["time"])

        if 'layer2' in e and e['layer2'] != {}:
            row.append(e['layer2']['src_addr'])
            row.append(e['layer2']['dest_addr'])
        else:
            row.append('')
            row.append('')
            row.append('')
            row.append('')
            row.append(apptype['ack'])
            row.append('')
            return row


        if 'layer3' in e and e['layer3'] != {}:
            if "fe80::" in e['layer3']['src']:
                row.append("fe80::2"+e['layer2']['src_addr'][3:])
            else:
                row.append(e['layer3']['src'])

            row.append(e['layer3']['dst'])
        else:
            row.append('')
            row.append('')
            row.append(apptype['control'])
            row.append('')
            return row

        if 'layer4' in e and e['layer4'] != {} and e['layer4'] != None:
            if e["layer4"]['protocol'] == 'CoAP':
                if e["layer4"]['code'] == 1 or \
                   e["layer4"]['code'] == "GET":
                    row.append(apptype['command'])
                    row.append('get_data')

                elif e["layer4"]['code'] == 2 or \
                   e["layer4"]['code'] == "POST":
                    row.append(apptype['command'])
                    row.append('send_data')                    

                else:
                    if e['layer4']['value'] == 'Ack':
                        row.append(apptype['ack'])
                        row.append("ACK")
                    else:
                        row.append(apptype['data'])
                        row.append(e["layer4"]['value'])

            # Currently, there are only two protocols: CoAP and DTLS
            # In the future, more protocols will be supported and 
            # an elif condition will be more suitable here
            else:
                # Packet with a length of 82 and 83 bytes 
                # are considered as ACK packets without data
                if e['length'] == 82 or e['length'] == 83:
                    row.append(apptype['ack'])
                    row.append('') 
                # For all other packets
                # we cannot exactly determine the correspoding 
                # type amongst GET, POST or ACk with data
                else:
                    row.append(apptype['unknown'])
                    row.append('')

        else:
            row.append(apptype['control'])
            row.append('')

        return row
        
    def BTLEConversion(self, pkt):
        """Return a row with the unified format if the packet (input) meets all the requirements  
        
        Extracts information from BTLE packet, analyzes it and converts it to the unified format
        if it corresponds to a data packet with specific information.
        """
        # This is the little dirty trick
        # We access to the global variable to get the packet
        packet = gpkts[pkt]
        row = []

        row.append('btle')
        
        # Print debug
        logging.debug(f"Packet[{pkt}] processed")

        e = self.extractor.extract_pkt_layers(packet)
        logging.debug(f"Packet[{pkt}] extracted: {e}")

        if 'Master' in e['layer2']['data header']:
            row.append(f"mst-{e['layer2']['data header']['Master']}")
            row.append(f"slv-{e['layer2']['data header']['Slave']}")
            return row

        row.append(e["time"])
        row.append(e['src'])
        row.append(e['dst'])
        row.append(e['src'])
        row.append(e['dst'])
            
        # We only focus on data packet
        if 'layer4' not in e:
            row.append(apptype['control'])
            row.append('')
            return row

        # We are only interested by Read Request/response
        # and Handle Value Indication/Write Command
        # Currently I only need packets with those opcode
        opCode = list(bleConstants.opCode.keys())
        opCode.remove(0x0a)
        opCode.remove(0x0b)
        opCode.remove(0x52)
        opCode.remove(0x1d)
        # opCode.remove(0x08)
        # opCode.remove(0x09)
        
        if self.verbose:
            opCode = list(bleConstants.opCode.values())
            opCode.remove('Read Request')
            opCode.remove('Read Response')
            opCode.remove('Write Command')
            opCode.remove('Handle Value Indication')
            # opCode.remove('Read By Type Response')
            # opCode.remove('Read By Type Request')

        if e['layer4'] == {}:
            row.append(apptype['unknown'])
            row.append('')
            return row
            
        if e['layer4']['opcode'] in opCode:
            row.append(apptype['control'])
            row.append('')
            return row

        #### AppType ####        
        if (e['layer4']['opcode'] == 'Read Request' or \
            e['layer4']['opcode'] == 0x0a or \
            e['layer4']['opcode'] == 'Write Command' or \
            e['layer4']['opcode'] == 0x52):
            # It corresponds to a sensor scheme initialised by the controller
            # And we define it with get_data
            row.append(apptype['command'])
            row.append('get_data')

        elif (e['layer4']['opcode'] == 'Read Response' or \
              e['layer4']['opcode'] == 0x0b or \
              e['layer4']['opcode'] == 'Handle Value Indication' or \
              e['layer4']['opcode'] == 0x1d):
            row.append(apptype['data'])
            row.append('value')
            # handles = e['layer4']['handles']
            # row.append(handles.pop(0)['value']['UUID'])
            # if len(handles) > 0:
            #     for handle in handles:
            #         row[-1] += ':-:' + handle["value"]["UUID"]
            
        else:
            row.append(apptype['control'])
            row.append(e['layer4']['value'])

        logging.debug(f"Packet[{pkt}] : {row}")
        return row
    
    def ZigBeeConversion(self, pkt):
        """Return a row with the unified format if the packet (input) meets all the requirements  
        
        Extracts information from ZigBee packet, analyzes it and converts it to the unified format
        if it corresponds to a data packet with specific information.
        """
        # This is the little dirty trick
        # We access to the global variable to get the packet
        #packet = self.pkts[pkt]
        packet = gpkts[pkt]
        
        # Print debug
        logging.debug(f"Packet[{pkt}] processed")
        # We check if the packet is well formed
        # And the fcs is correct
        # So we compute the fcs and compare it to the one store in the packet
        try:
            fcs = int.from_bytes(packet.compute_fcs(bytes_encode(packet)[:-2]), 'little')
        except:
            return None
        
        if fcs != packet.fcs:
            return None
            
        #e = extractor.extract_pkt_info(packet)
        e = self.extractor.extract_pkt_info(packet)
        logging.debug(f"Packet[{pkt}] extracted: {e}")
        # We are only interested in ZCL Packets
        # So if the packet is an 802.15.4 ACK or DATA
        # then we ignore this packet and only focus on data packets

        if e is None:
            return None
        
        row = []
        row.append('zigbee')    

        if "transmission" in e:

            if "transmission2" in e["transmission"]:
                row.append(e["transmission"]["time"])
                row.append(e["transmission"]["transmission2"]['src'])
                row.append(e["transmission"]["transmission2"]['dst'])

            if "transmission4" in e["transmission"]:

                if 'srcshort' in e["transmission"]["transmission3"]:
                    row.append(e["transmission"]["transmission3"]['srcshort'])
                    row.append(e["transmission"]["transmission3"]['dstshort'])
                else :
                    return None

                transmission4 = e["transmission"]["transmission4"]
                
                # The application layer is not encrypted
                if transmission4 != {}:

                    # We only check for data aps_frametype and HA profile
                    # As for 802.15.4 ACK, aps one are not interesting
                    if self.verbose:
                        if transmission4['profile'] != 'HA_Home_Automation' or \
                           transmission4['aps_frametype'] == 'ack':
                            return None
                    else:
                        if transmission4['profile'] != 0x0104 or \
                           transmission4['aps_frametype'] == 2:
                            return None

                    # tmp only focus on cluster "temperature_measurement" and "on_off"
                    good_cluster = [0x0006, 0x0402]
                    if self.verbose:
                        good_cluster = ["temperature_measurement", "on_off"]

                    if transmission4['cluster'] not in good_cluster:
                        return None
                
                    if 'zcl_frametype' in transmission4:
                        zcl_frametype = transmission4['zcl_frametype']
                    else:
                        return None
                
                    ####  Apptype ####
                    
                    # ZCl_frametype
                    # 1 -> Cluster-wide : In our case it means 'send command'
                    # So apptype is actuator and the command is stored in e["transmission"]["transmission4"]['command']
                    if zcl_frametype == 1 or zcl_frametype == 'cluster-specific':
                        if 'command' in transmission4:
                            row.append(apptype['command'])
                            row.append(transmission4['command'])
                        else:
                            # An error
                            return None 

                    # In the case of profile-wide zcl_apptype
                    # It correspond to sensor apptype
                    # but the data can be different, it is either get_data or the data itself
                    elif zcl_frametype == 0 or zcl_frametype == 'profile-wide':
                        row.append(apptype['data'])

                        command_identifier = transmission4['command_identifier']
                        if command_identifier == 'read attributes response' or command_identifier == 0x01:
                            # TODO : make a conversion structure according to the type of data
                            # Here we are only 2 data types : Boolean (16) or signed int (41)
                            datatype = transmission4['read_attributes_status_records'][0]['attribute_data_type']
                            # boolean
                            if datatype == 16:
                                data = int.from_bytes(transmission4['read_attributes_status_records'][0]['attribute_value'], 'little')
                                row.append('On' if data else 'Off')

                            #Unsigned Int
                            elif datatype == 41:
                                data = int.from_bytes(transmission4['read_attributes_status_records'][0]['attribute_value'], 'little')
                                row.append(data)

                        # We don't consider default response as interesting message
                        elif command_identifier == 'report attributes' or command_identifier == 0x0a:
                            row = None
                            
                        # We don't consider default response as interesting message
                        elif command_identifier == 'default response' or command_identifier == 0x0b:
                            return None

                        else :
                            row.append('get_data')
                
                # Encrypted application layer
                else:
                    # All packets with a length inferor to 49 is in reality an APS ack 
                    if e['transmission']['length'] < 48:
                        row.append(apptype['ack'])
                        row.append('')
                        #return row    

                    # The packet with a length of 52 bytes is a control packet 
                    # sent to inform the ZigBee hub a status modification
                    elif e['transmission']['length'] == 52 or e['transmission']['length'] == 53:
                        row.append(apptype['control'])
                        row.append('')

                    # All packets with a length inferor to 47 is in reality an APS ack 
                    elif e['transmission']['length'] >= 70:
                        row.append(apptype['ack'])
                        row.append('')
                        #return row 
                    else :
                        row.append(apptype['unknown'])
                        row.append('')

            # It's a 802.15.4 packet 
            else:
                row.append('')
                row.append('')
                row.append('')
                row.append('')

        # Something wrong happened :: 
        else:
            return None

        logging.debug(f"Packet[{pkt}] : {row}")
        return row

# This function convert a list of packet from a specific protocol to a list
# of packet using the unified format.
def gen_packet(pcap: str, protocol: str, nbThread: int, debug: bool):
    
    nbThread = nbThread
    protocol = protocol
    verbose = debug
    
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s:%(message)s"
    )

    logging.info(f"[i] Pcap from protocol {protocol} will be processed")

    if protocol == 'ZIGBEE':
        from .extractors import zigbeeextractor
        conf.dot15d4_protocol = 'zigbee'
    elif protocol == 'OS4I':
        from .extractors import sixlowpanextractor
        conf.dot15d4_protocol = 'sixlowpan'
        
    try:
        logging.debug(f"[d] Read Pcap File")
        pkts = rdpcap(pcap)
    except:
        logging.error('Error while opening the file...')
        logging.error(f'{pcap}')
        exit(1)

    # Clean the os4i pcap file to remove all retransmissions packets
    # It means remove all messages sent with the same MID in both request and response
    # if 'OS4I' in protocol:
    #     logging.info(f"[i] Cleaning Pcap files to erase retransmission communications")
    #     pkts = sixlowpanextractor.cleanCoAPPcap(pkts)
        
    global gpkts
    gpkts = pkts
   
    genPacket = PacketGenerator(protocol, len(pkts), nbThread, verbose)

    rows = genPacket.convertPackets()
    
    # CSV format
    # protocol, timestamp, dlsrc, dldst, nwksrc, nwkdst, apptype, data
    csvData = list(filter(None, rows)) 

    if 'BTLE' in protocol:
        for row in csvData:
            if len(row) == 3:
                genPacket.BTLEAddr['Master'] = row[1][4:]
                genPacket.BTLEAddr['Slave'] = row[2][4:]
                while row in csvData:
                    csvData.remove(row)

    # Let order the list by timestamp
    # csvData.sort(key=lambda x: x[0])
    if 'BTLE' in protocol:
        csvDataTmp = []
        for row in csvData:
            row = [r.replace('Slave', genPacket.BTLEAddr['Slave']) if isinstance(r, str) else r for r in row]
            row = [r.replace('Master', genPacket.BTLEAddr['Master']) if isinstance(r, str) else r for r in row]
            csvDataTmp.append(row)

        csvData = csvDataTmp
            
    logging.info(f"[i] The process is ending")
    
    return csvData
