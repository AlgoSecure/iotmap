from scapy.utils import *
from utils.crypto.utils import key_net
from utils.crypto.zigbee_crypto import zigbee_decrypt

from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *

conf.dot15d4_protocol="zigbee"

class ZigbeeExtractor():
    """
    ZigBee extractor. Extracts informations from ZigBee packets. 
    Decrypts the ZigBee packets if key and decryption are specified.
    Call extract_pkt_info to get the packet informations in a list.
    """
    def __init__(self, args):
        key, self.decryption, self.verbose = args
        self.index = 0
        # Get key from utils2 if key unset but decryption wanted
        if key is None and self.decryption:
            self.key = key_net
        else:
            self.key = key

    def extract_pkt_info(self, pkt):
        """
        Extracts all layers specific information from header.
        Returns [src, dst, transmission] list containing all relevant informations.
        """
        src, dst, transmission = {}, {}, {}
        transmission['time'] = pkt.time
   
        # Extract information from layer 2
        extract2 = self.extract_pkt_info2(pkt)
        transmission['transmission2'] = extract2['transmission2']
        src['src2'] = extract2['src']
        dst['dst2'] = extract2['dst']

        # Extract information from layer 3 and up
        if ZigbeeNWK in pkt or ZigBeeBeacon in pkt:
            extract3 = self.extract_pkt_info3(pkt)
            if extract3 is None:
                return None
            transmission['transmission3'] = extract3['transmission3']
            transmission['transmission4'] = extract3['transmission4']
            src['src'] = extract3['src']
            dst['dst'] = extract3['dst']

        # Update index
        transmission['index'] = self.index
        self.index += 1

        # Return [src, dst, transmission]
        ret = {}
        ret['src'] = src
        ret['dst'] = dst
        ret['transmission'] = transmission

        return ret

    def extract_pkt_info2(self, pkt):
        """
        Extracts 802.15.4 specific information from header to update node/transmission state
        Called by extract_pkt_info().
        """        
        src, dst = {}, {},
        transmission2 = {}

        # Set addresses
        src['ZBshort'] = pkt.src_addr if (pkt.fcf_srcaddrmode == 2 and hasattr(pkt, "src_addr")) else -1
        dst['ZBshort'] = pkt.dest_addr if (pkt.fcf_destaddrmode == 2 and hasattr(pkt, "dest_addr")) else -1
        src['ZBlong'] = pkt.src_addr if (pkt.fcf_srcaddrmode == 3 and hasattr(pkt, "src_addr")) else -1           
        dst['ZBlong'] = pkt.dest_addr if (pkt.fcf_destaddrmode == 3 and hasattr(pkt, "dest_addr")) else -1

        # Set PANID for both src and dst
        src['panid'] = pkt.src_panid if (hasattr(pkt, "src_panid") and not not pkt.src_panid) else -1
        dst['panid'] = pkt.dest_panid if (hasattr(pkt, "dest_panid") and not not pkt.dest_panid) else -1
        # Set with the other PANID if needed
        if src['panid'] == -1 and dst['panid'] != -1:
            src['panid'] = dst['panid']
        if dst['panid'] == -1 and src['panid'] != -1:
            dst['panid'] = src['panid']
        

        transmission2['src'] = src['ZBshort'] if src['ZBshort'] != -1 else src['ZBlong']
        transmission2['dst'] = dst['ZBshort'] if dst['ZBshort'] != -1 else dst['ZBlong']
        transmission2['src_panid'] = src['panid']
        transmission2['dst_panid'] = dst['panid']

        # Info from FCF (all packets)
        if hasattr(pkt, "fcf_security"):
            transmission2['sec_enabled'] = pkt.fcf_security # 0 or 1
            transmission2['proto_version'] = pkt.fcf_framever

        if hasattr(pkt, "source") and hasattr(pkt, "src_addr") and pkt.fcf_srcaddrmode == 2:
            if pkt.source != pkt.src_addr: # Different layer2/layer3 addresses : routing
                src['router_capacity'] = 1

        if hasattr(pkt, "fcf_frametype"):
            # Info from MAC command packets (frametype 3)
            if pkt.fcf_frametype == 3:
                if hasattr(pkt, "cmd_id") and pkt.cmd_id == 1: # aka if pkt.haslayer(Dot15d4Cmd)
                    src['dev_class'] = pkt.device_type # RFD or FFD
                    src['alt_PANcoord'] = pkt.alternate_pan_coordinator # 0 or 1
                    src['rx_on_idle'] = pkt.receiver_on_when_idle
                    src['power_source'] = pkt.power_source
                    src['sec_capability'] = pkt.security_capability # 0 or 1
                
                # Association Response
                if hasattr(pkt, "cmd_id") and pkt.cmd_id == 2: 
                    if src_dst == SRC:
                        src['coord'] = 1
                        src['PANcoord'] = 1
                    if hasattr(pkt, "association_status"):
                        dst['assoc_status'] = pkt.association_status

            # Type
            if pkt.fcf_frametype == 0:
                transmission2['type'] = "802.15.4 Beacon"
            elif pkt.fcf_frametype == 1:
                transmission2['type'] = "802.15.4 Data"
            elif pkt.fcf_frametype == 2:
                transmission2['type'] = "802.15.4 ACK"
            elif pkt.fcf_frametype == 3:
                transmission2['type'] = "802.15.4 MAC Command"

        # ZigBeeBeacon : layer 2 is relevant
        if ZigBeeBeacon in pkt and pkt.fcf_frametype == 0:  
            src['coord'] = 1 # coordinator
            src['PANcoord'] = pkt.sf_pancoord # PAN coordinator
            src['sf'] = {}
            src['sf']['assocpermit'] = pkt.sf_assocpermit
            src['sf']['finalcapslot'] = pkt.sf_finalcapslot
            src['sf']['beacon_interval'] = pkt.sf_beaconorder
            src['sf']['sf_interval'] = pkt.sf_sforder

        # Convert values to hex
        for record in [src, dst, transmission2]:
            for k in record.keys():
                if k in values_to_hex:
                    if record[k] != -1:
                        record[k] = hex(record[k])

        ret = {
            'src': src,
            'dst': dst,
            'transmission2': transmission2,
        }
        return ret

    def extract_pkt_info3(self, pkt):
        """
        Extracts Zigbee specific information from header to update node/transmission state
        Called by extract_pkt_info().
        """
        src, dst = {}, {}
        transmission3, transmission4 = {}, {}

        # ZigbeeBeacon
        if ZigBeeBeacon in pkt:
            transmission3['proto_id'] = pkt.proto_id # 1 byte
            transmission3['proto_version'] = pkt.nwkc_protocol_version # 4 bits
            transmission3['stack_profile'] = pkt.stack_profile # 4 bits
            src['end_dev_capacity'] = pkt.end_device_capacity
            src['device_depth'] = pkt.device_depth # 4 bits
            src['router_capacity'] = pkt.router_capacity
            if hasattr(pkt, "extended_pan_id"):
                transmission3['epid'] = pkt.extended_pan_id # 8 bytes

        # ZigbeeNWKCommand
        if ZigbeeNWKCommandPayload in pkt:
            if pkt.cmd_identifier == 6: # capability information
                src['sec_capability'] = pkt.security_capability
                src['rx_on_idle'] = pkt.receiver_on_when_idle
                src['power_source'] = pkt.power_source
                src['dev_class'] = pkt.device_type
                src['alt_PANcoord'] = pkt.alternate_pan_coordinator
            elif pkt.cmd_identifier == 7:
                dst['ZBshort'] = pkt.network_address
                dst['assoc_status'] = pkt.rejoin_status
            elif pkt.cmd_identifier == 9:
                src['epid'] = pkt.epid
                dst['epid'] = pkt.epid

        # ZigbeeNWK
        if ZigbeeNWK in pkt:
            transmission3['proto_version'] = pkt.proto_version
            
            # Addresses / PANID
            src['ZBshort'] = pkt.source
            dst['ZBshort'] = pkt.destination
            src['ZBlong'] = pkt.ext_src if pkt.flags & 16 else -1            
            dst['ZBlong'] = pkt.ext_dst if pkt.flags & 8 else -1
            src['panid'], dst['panid'] = -1, -1
            if hasattr(pkt, "src_panid") and not not pkt.src_panid:
                src['panid'] = pkt.src_panid
            if hasattr(pkt, "dest_panid") and not not pkt.dest_panid:
                dst['panid'] = pkt.dest_panid
            if (src['panid'] == -1 and dst['panid'] != -1):
                src['panid'] = dst['panid']
            if (dst['panid'] == -1 and src['panid'] != -1):
                dst['panid'] = src['panid']
            

            transmission3['srcshort'] = src['ZBshort']
            transmission3['dstshort'] = dst['ZBshort']
            transmission3['srclong'] = src['ZBlong']
            transmission3['dstlong'] = dst['ZBlong']            
            transmission3['panid'] = src['panid']

            layer = pkt.getlayer(ZigbeeNWK)
            transmission3['seqnum'] = layer.seqnum if hasattr(pkt, "seqnum") else -1
            transmission3['sec_enabled'] = True if layer.flags & 0x02 else -1

        # ZigbeeSecHeader
        if ZigbeeSecurityHeader in pkt: # or just pkt.flags & 0x02
            src['last_fc'] = pkt.fc # framecounter
            transmission3['seclevel'] = pkt.nwk_seclevel

        # ZigbeeAppDataCommand
        # No information to retrieve

        # Zigbee "Transmission Type"
        if ZigBeeBeacon in pkt:
            transmission3['type'] = "Zigbee Beacon"
        elif pkt.frametype == 0:
            transmission3['type'] = "Zigbee Data"
        elif pkt.frametype == 1:
            transmission3['type'] = "Zigbee Command"


        # Decryption for ZigbeeAppDataPayload / ZigbeeClusterLibrary
        if self.decryption and ZigbeeSecurityHeader in pkt:
            # Decrypt packet
            decrypted_pkt = zigbee_decrypt(pkt, self.key)
            ok_decryption, ok_interpretation = True, True

            if isinstance(decrypted_pkt, bytes) or decrypted_pkt is None:
                return None
            
            else:
                try:
                    if (ZigbeeAppDataPayload in decrypted_pkt and decrypted_pkt.cluster is None): # Check whether Scapy interpreted packet wrongly
                        ok_interpretation = False
                except TypeError:
                        ok_interpretation = False
                    
            if ok_decryption and ok_interpretation:
                
                # ZigbeeAppDataPayload
                if ZigbeeAppDataPayload in decrypted_pkt:
                    layer = decrypted_pkt[ZigbeeAppDataPayload]
                    transmission4['src_endpoint']= layer.src_endpoint if hasattr(layer, 'src_endpoint') else -1
                    transmission4['dst_endpoint']= layer.dst_endpoint if hasattr(layer, 'dst_endpoint') else -1
                    transmission4['delivery_mode'] = layer.delivery_mode if hasattr(layer, 'delivery_mode') else -1
                    transmission4['counter'] = layer.counter if hasattr(layer, 'counter') else -1
                    
                    if self.verbose == 0:
                        transmission4['cluster'] = layer.cluster if hasattr(layer, 'cluster') else -1
                        transmission4['profile'] = layer.profile if hasattr(layer, 'profile') else -1
                        transmission4['aps_frametype'] = layer.aps_frametype if hasattr(layer, 'aps_frametype') else -1
                    else:
                        transmission4['cluster'] = clusters[layer.cluster] if (hasattr(layer, 'cluster') and layer.cluster in clusters) else "cluster unknown"
                        transmission4['profile'] = profiles[layer.profile] if (hasattr(layer, 'profile') and layer.profile in profiles) else "profile unknown"
                        transmission4['aps_frametype'] = aps_frametypes[layer.aps_frametype] if (hasattr(layer, 'aps_frametype') and layer.aps_frametype in aps_frametypes) else "aps_frametype unknown"
                        
                    transmission4['type'] = [transmission4['cluster'], transmission4['profile']]


                    # ZigbeeClusterLibrary
                    if ZigbeeClusterLibrary in decrypted_pkt:
                        layer = decrypted_pkt[ZigbeeClusterLibrary]
                        transmission4['direction'] = layer.direction
                        transmission4['manufacturer_specific'] = layer.manufacturer_specific
                        transmission4['zcl_frametype'] = layer.zcl_frametype if (self.verbose == 0 or layer.zcl_frametype not in zcl_frametype) else zcl_frametype[layer.zcl_frametype]
                        transmission4['transaction_sequence'] = layer.transaction_sequence if (hasattr(layer, 'transaction_sequence') and layer.transaction_sequence is not None) else -1 # Level 5 counter
                        transmission4['manufacturer_code'] = layer.manufacturer_specific if (hasattr(layer, 'manufacturer_code') and layer.manufacturer_specific is not None) else -1
                
                        command_identifier = -1 # Set default unknown command_identifier
                        if hasattr(layer, 'command_identifier'):
                            transmission4['command_identifier'] = layer.command_identifier if (self.verbose == 0 or layer.command_identifier not in zcl_command_identifiers) else zcl_command_identifiers[layer.command_identifier]

                            command_identifier = layer.command_identifier
                            # Important parameter : which ZCL command is used, according to cluster

                        # ZigbeeClusterLibrary "Payload" : Read Attributes
                        if ZCLGeneralReadAttributes in decrypted_pkt: # Only if command_identifier = 0x00
                            general_read = {
                                'attribute_identifiers': decrypted_pkt[ZCLGeneralReadAttributes].attribute_identifiers,
                            }
                            transmission4['general_read_attributes'] = general_read
                            # List of attribute identifiers


                        # ZigbeeClusterLibrary "Payload" : Read Attributes Response
                        elif ZCLGeneralReadAttributesResponse in decrypted_pkt: # Only if command_identifier = 0x01
                            layer = decrypted_pkt[ZCLGeneralReadAttributesResponse]
                            
                            l_records = []
                            for l in layer.read_attribute_status_record:
                                if ZCLReadAttributeStatusRecord in l:
                                    l_records.append(l)

                            records = []
                            for l in l_records:
                                record = {}
                                record['attribute_identifier'] = l.attribute_identifier if hasattr(l, "attribute_identifier") else -1
                                record['attribute_data_type'] = l.attribute_data_type if hasattr(l, "attribute_data_type") else -1
                                record['attribute_value'] = l.attribute_value if hasattr(l, "attribute_value") else -1
                                records.append(record)

                            transmission4['read_attributes_status_records'] = records

                        # TODO after : implement support for Write Attributes when Scapy supports it (only read is supported as of now)
                        
                        # If the zcl frametype is profile wide
                        if transmission4['zcl_frametype'] == 1:
                            transmission4["command"] = 'On' if command_identifier == 1 else 'Off'
        

            # Experimental manuel parser to use when Scapy fails : mainly parses READ ATTRIBUTES ZCL PACKETS
            elif ok_decryption and not ok_interpretation and len(raw(decrypted_pkt)) > 8:
                ## Debug info
                # print("Go parser")
                # print(pkt.summary())
                # print(decrypted_pkt.summary())
                # print(raw(decrypted_pkt))

                # ZigbeeAppDataPayload
                raw_dpkt = raw(decrypted_pkt)
                transmission4['src_endpoint']= raw_dpkt[6]
                transmission4['dst_endpoint']= raw_dpkt[1]
                transmission4['delivery_mode'] = (raw_dpkt[0] >> 2 & 3) # Get 2nd and 3rd bits counting from the right
                transmission4['counter'] = raw_dpkt[7]

                cluster = int('0x' + '{:02x}'.format(raw_dpkt[3]) + '{:02x}'.format(raw_dpkt[2]), 0)
                profile = int('0x' + '{:02x}'.format(raw_dpkt[5]) + '{:02x}'.format(raw_dpkt[4]), 0)
                aps_frametype = raw_dpkt[0] & 3 # We only want the 2 lower bits (000000xx)
                
                if self.verbose == 0:
                    transmission4['cluster'] = cluster
                    transmission4['profile'] = profile
                    transmission4['aps_frametype'] = aps_frametype
                else:
                    transmission4['cluster'] = clusters[cluster] if (cluster in clusters) else "cluster unknown"
                    transmission4['profile'] = profiles[profile] if (profile in profiles) else "profile unknown"
                    transmission4['aps_frametype'] = aps_frametypes[aps_frametype] if (aps_frametype in aps_frametypes) else "aps_frametype unknown"

                transmission4['type'] = [transmission4['cluster'], transmission4['profile']]

                if profile == 0x0104: # We only want HA
                
                    # ZigbeeClusterLibrary
                    transmission4['direction'] = raw_dpkt[8] >> 3 & 1
                    transmission4['manufacturer_specific'] = raw_dpkt[8] >> 2 & 1
                    transmission4['zcl_frametype'] = raw_dpkt[8] & 3 # We only want the 2 lower bits (000000xx)
                    transmission4['transaction_sequence'] = raw_dpkt[9]
                    command_identifier = raw_dpkt[10]
                    
                    # If the zcl frametype is profile wide
                    if transmission4['zcl_frametype'] == 0:
                        if self.verbose > 0:
                            if command_identifier in zcl_command_identifiers:
                                transmission4['command_identifier'] = zcl_command_identifiers[command_identifier]
                            else:
                                transmission4['command_identifier'] = "unknown command"
                        else:
                            transmission4['command_identifier'] = command_identifier
                            
                            if command_identifier == 0:
                                general_read = {
                                    'attribute_identifiers': int('0x' + '{:02x}'.format(raw_dpkt[12]) + '{:02x}'.format(raw_dpkt[11]), 0)
                                }
                                transmission4['general_read_attributes'] = general_read
                                
                                # ZigbeeClusterLibrary "Payload" : Read Attributes Response
                            elif command_identifier == 1: # Only if command_identifier = 0x01                        
                                records = []
                                # Only use a single record of read attribute response for now, but there could be multiple potentially, which means more complex parsing
                                record = {}
                                record['attribute_identifier'] = int('0x' + '{:02x}'.format(raw_dpkt[12]) + '{:02x}'.format(raw_dpkt[11]), 0)
                                record['attribute_data_type'] = raw_dpkt[14]
                                record['attribute_value'] = raw_dpkt[15]
                                records.append(record)
                                
                                transmission4['read_attributes_status_records'] = records
                            
                                # The ZCL frametype is Cluster wide -> Send command
                    elif transmission4['zcl_frametype'] == 1:
                        transmission4["command"] = 'On' if command_identifier == 1 else 'Off'
                                

        # Values to display as hex
        for record in [src, dst, transmission3, transmission4]:
            for k in record.keys():
                if k in values_to_hex:
                    if record[k] != -1:
                        record[k] = hex(record[k])

        ret = {}
        ret['src'] = src
        ret['dst'] = dst
        ret['transmission3'] = transmission3
        ret['transmission4'] = transmission4

        return ret    
             

# Values to format as hex
values_to_hex = ['ZBshort', 'ZBlong', 'panid', 'src', 'dst', 'src_panid', 'dst_panid', 'srcshort', 'dstshort', 'srclong', 'dstlong']

# APS identifiers
aps_frametypes = {
    2: 'ack',
    0: 'data'
}

# ZigBee identifiers
zcl_frametype = {
    0: 'profile-wide',
    1: 'cluster-specific',
    2: 'reserved2',
    3: 'reserved3',
}

zcl_command_identifiers = {
    0x00: "read attributes",
    0x01: "read attributes response",
    0x02: "write attributes",
    0x03: "write attributes undivided",
    0x04: "write attributes response",
    0x05: "write attributes no response",
    0x06: "configure reporting",
    0x07: "configure reporting response",
    0x08: "read reporting configuration",
    0x09: "read reporting configuration response",
    0x0a: "report attributes",
    0x0b: "default response",
    0x0c: "discover attributes",
    0x0d: "discover attributes response",
    0x0e: "read attributes structured",
    0x0f: "write attributes structured",
    0x10: "write attributes structured response",
    0x11: "discover commands received",
    0x12: "discover commands received response",
    0x13: "discover commands generated",
    0x14: "discover commands generated response",
    0x15: "discover attributes extended",
    0x16: "discover attributes extended response",        
}

profiles = {
    0x0000: "ZigBee_Device_Profile", # ZigBee_Stack_Profile_1
    0x0101: "IPM_Industrial_Plant_Monitoring",
    0x0104: "HA_Home_Automation",
    0x0105: "CBA_Commercial_Building_Automation",
    0x0107: "TA_Telecom_Applications",
    0x0108: "HC_Health_Care",
    0x0109: "SE_Smart_Energy_Profile",
}

clusters = {
    # Functional Domain: General
    0x0000: "basic",
    0x0001: "power_configuration",
    0x0002: "device_temperature_configuration",
    0x0003: "identify",
    0x0004: "groups",
    0x0005: "scenes",
    0x0006: "on_off",
    0x0007: "on_off_switch_configuration",
    0x0008: "level_control",
    0x0009: "alarms",
    0x000a: "time",
    0x000b: "rssi_location",
    0x000c: "analog_input",
    0x000d: "analog_output",
    0x000e: "analog_value",
    0x000f: "binary_input",
    0x0010: "binary_output",
    0x0011: "binary_value",
    0x0012: "multistate_input",
    0x0013: "multistate_output",
    0x0014: "multistate_value",
    0x0015: "commissioning",
    # 0x0016 - 0x00ff reserved
    # Functional Domain: Closures
    0x0100: "shade_configuration",
    # 0x0101 - 0x01ff reserved
    # Functional Domain: HVAC
    0x0200: "pump_configuration_and_control",
    0x0201: "thermostat",
    0x0202: "fan_control",
    0x0203: "dehumidification_control",
    0x0204: "thermostat_user_interface_configuration",
    # 0x0205 - 0x02ff reserved
    # Functional Domain: Lighting
    0x0300: "color_control",
    0x0301: "ballast_configuration",
    # Functional Domain: Measurement and sensing
    0x0400: "illuminance_measurement",
    0x0401: "illuminance_level_sensing",
    0x0402: "temperature_measurement",
    0x0403: "pressure_measurement",
    0x0404: "flow_measurement",
    0x0405: "relative_humidity_measurement",
    0x0406: "occupancy_sensing",
    # Functional Domain: Security and safethy
    0x0500: "ias_zone",
    0x0501: "ias_ace",
    0x0502: "ias_wd",
    # Functional Domain: Protocol Interfaces
    0x0600: "generic_tunnel",
    0x0601: "bacnet_protocol_tunnel",
    0x0602: "analog_input_regular",
    0x0603: "analog_input_extended",
    0x0604: "analog_output_regular",
    0x0605: "analog_output_extended",
    0x0606: "analog_value_regular",
    0x0607: "analog_value_extended",
    0x0608: "binary_input_regular",
    0x0609: "binary_input_extended",
    0x060a: "binary_output_regular",
    0x060b: "binary_output_extended",
    0x060c: "binary_value_regular",
    0x060d: "binary_value_extended",
    0x060e: "multistate_input_regular",
    0x060f: "multistate_input_extended",
    0x0610: "multistate_output_regular",
    0x0611: "multistate_output_extended",
    0x0612: "multistate_value_regular",
    0x0613: "multistate_value",
    # Smart Energy Profile Clusters
    0x0700: "price",
    0x0701: "demand_response_and_load_control",
    0x0702: "metering",
    0x0703: "messaging",
    0x0704: "smart_energy_tunneling",
    0x0705: "prepayment",
    # Functional Domain: General
    # Key Establishment
    0x0800: "key_establishment",
    # Clusters found in other resources
    0x0b05: "diagnostics",
    0x0020: "poll_control",
    0x001a: "power_profile",
    0x0b01: "meter_identification",
    0x1fee: "unknown",
}

# Application Profile IDs are 16-bit numbers and range from 0x0000 to 0x7fff for public profiles and 0xbf00 to 0xffff for manufacturer-specific profiles. 
# Manufacturer code -> Profile, not cluster

# EP + Profile + Group : -> define Cluster -> Define Command/Attributes
    
# http://www.zigbee.org/~zigbeeor/wp-content/uploads/2014/10/07-5123-06-zigbee-cluster-library-specification.pdf
