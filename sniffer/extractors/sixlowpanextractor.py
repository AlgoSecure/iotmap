from scapy.utils import *
from scapy.layers.dot15d4 import *
from scapy.layers.tls import *
from scapy.layers.inet6 import *
from scapy.layers.sixlowpan import *
from scapy.contrib.coap import *

conf.dot15d4_protocol = 'sixlowpan'

class SixLowPANExtractor():
    """
    6lowpan extractor. Extracts informations from 6lowpan packets. 
    Call extract_pkt_info to get the packet informations in a list.
    """
    def __init__(self, args):
        self.verbose = args[0]
        self.index = 0

    # need some improvements in the futur
    def extract_pkt_layers(self, pkt):
        """
        Extracts all layers specific information from header.
        Returns [src, dst, transmission] list containing all relevant informations.
        """
        layers = {}
        layers['time'] = float(pkt.time)
        layers['length'] = len(pkt)

        layers['RFlayer'] = self.extract_pkt_rflayer(pkt)
        
        if Dot15d4Data in pkt:
            layers['layer2'] = self.extract_pkt_layer2(pkt)

        if LoWPAN_IPHC in pkt:
            layers['layer3'] = self.extract_pkt_layer3(pkt)

        if UDP in pkt:
            layers['layer4'] = self.extract_pkt_layer4(pkt)
                
        return layers

    def extract_pkt_rflayer(self, pkt):
        """
        Extracts OS4I specific information from header to update node/transmission state
        Called by extract_pkt_info(). 
        This layer is relative to the radio specificities
        """
        rflayer = {
            'fcf_reserved_1'   : pkt.fcf_reserved_1,
            'fcf_panidcompress': pkt.fcf_panidcompress,
            'fcf_ackreq'       : pkt.fcf_ackreq, 
            'fcf_pending'      : pkt.fcf_pending, 
            'fcf_security'     : pkt.fcf_security, 
            'fcf_frametype'    : dot15d4_fcf_frametype[pkt.fcf_frametype] if self.verbose else pkt.fcf_frametype, 
            'fcf_srcaddrmode'  : pkt.fcf_srcaddrmode, 
            'fcf_framever'     : pkt.fcf_framever, 
            'fcf_destaddrmode' : pkt.fcf_destaddrmode, 
            'fcf_reserved_2'   : pkt.fcf_reserved_2, 
            'seqnum'           : pkt.seqnum, 
            'fcs'              : pkt.fcs,
        }

        return rflayer

    def extract_pkt_layer2(self, pkt):
        """
        Extracts OS4I specific information from header to update node/transmission state
        Called by extract_pkt_info(). 
        This layer contains information relative to 802.15.4 headers
        """
        layer2 = {}
        layer2["dest_panid"]=hex(pkt.dest_panid)
        layer2["dest_addr"]=hex_to_string(hex(pkt.dest_addr)) 
        layer2["src_addr"]=hex_to_string(hex(pkt.src_addr))

        return layer2

    def extract_pkt_layer3(self, pkt):
        """
        Extracts OS4I specific information from header to update node/transmission state
        Called by extract_pkt_info(). 
        This layer contains information relative to 6lowpan information
        """
        layer3 = {
            'src': pkt.src,
            'dst': pkt.dst
        }

        if ICMPv6RPL in pkt or ICMPv6EchoReply in pkt or ICMPv6EchoRequest in pkt :
            layer3['type'] = icmpv6_type[pkt.type] if self.verbose else pkt.type
            layer3['code'] = rplcodes[pkt.code] if self.verbose and pkt.code in rplcodes.keys() else pkt.code
            layer3['cksum'] = hex(pkt.cksum)

        return layer3

    def extract_pkt_layer4(self, pkt):
        """
        Extracts OS4I specific information from header to update node/transmission state
        Called by extract_pkt_info(). 
        This layer contains information relative to CoAP or DTLS layers
        """

        # If packet is in clear text
        # Check if CoAP is in the packet is equivalent to 
        # check if the source port or the dest port is egal to
        # 5683 (coap)
        layer4 = {}
        if CoAP in pkt:
            layer4 = {
                'protocol': 'CoAP',
                'code'    : coap_codes[pkt.code] if self.verbose and pkt.code in coap_codes.keys() else pkt.code
            }

            if pkt.code == 69:
                try:
                    layer4['value'] = pkt.load.decode('utf-8') if hasattr(pkt, 'load') else 'Ack'
                except:
                    # print("Timestamp : " + str(pkt.time))
                    return None
            elif pkt.code == 161:
                    layer4['value'] = 'test161'

            else:
                layer4['value'] = 'test'

        # Packet is encrypted
        # the port 5684 corresponds to coaps
        if pkt.sport == 5684 or pkt.dport == 5684:
            layer4 = self.DTLSDissector(pkt.load)


        return layer4

    # Until scapy supports DTLS 
    # This function is a non exhaustive DTLS dissector for
    # CoAP packets
    # DTLS format :
    #   - Content-type : 1 byte
    #   - Version      : 2 bytes
    #   - Epoch        : 2 bytes
    #   - Seq Number   : 6 bytes
    #   - Length       : 2 bytes
    #   - Message      : {Length} bytes
    def DTLSDissector(self, pkt):
        content_type = int(pkt[0])
        version = '0x' + str(pkt[1:3].hex())
        epoch = int.from_bytes(pkt[3:5], byteorder='big')
        seq = int.from_bytes(pkt[5:11], byteorder='big')
        length = int.from_bytes(pkt[11:13], byteorder='big')
        message = pkt[13:]

        if content_type == 22:
            if self.verbose:
                ct = dtls_client_hello[int(message[0])]
            else:
                ct = int(message[0])

            content_type = ct
        else:
            content_type = dtls_content_type[content_type]


        dtls = {
            'protocol'    : 'DTLS',
            'Content-type': content_type,
            'version'     : dtls_version[version] if self.verbose else version, 
            'epoch'       : epoch,
            'seq'         : seq,
            'length'      : length,
        }

        return dtls


# This function is used to convert address got in hex format
# to a string with IPv6 format
# Fo ex :
# '0x124b000e0d8257' -> 00:12:4b:00:0e:0d:82:57
def hex_to_string(address):
    if len(address) == 16:
        address = address.replace('x', '0')
    else:
        address = address[2:]

    string = ""
    for i in range(0, len(address) - 2, 2):
        string += address[i:i+2] + ':'
        
    return string[:-1]

def cleanCoAPPcap(pkts):
    """
    This function sort the pcap to remove possible duplicate in the coap pcap
    This is very useful for pcap generated through network using the contiki-os 
    software.
    This issue seems to be solved with the contiki-ng solution.
    """
    pcap = []
    coapPkts = []
    MID = []

    for x in pkts:
        if CoAP in x and (x.code==1 or x.code==2 or x.code==69):
            coapPkts.append(x)
            MID.append(x.msg_id)

        else :
            pcap.append(x)

    MID = list(set(MID))

    f_pkts = []

    for mid in MID:
        for c in [1, 2, 69]:
            pkt = [x for x in coapPkts if x.msg_id == mid and x.code==c]
            if len(pkt) > 0 :
                pkt.sort(key=lambda x: x.time)
            else :
                continue
            f_pkts.append(pkt[-1])
    
    pcap = pcap + f_pkts
    pcap.sort(key=lambda x: x.time)

    return pcap

coap_codes = {
    0: "Empty",
    # Request codes
    1: "GET",
    2: "POST",
    3: "PUT",
    4: "DELETE",
    # Response codes
    65: "2.01 Created",
    66: "2.02 Deleted",
    67: "2.03 Valid",
    68: "2.04 Changed",
    69: "2.05 Content",
    128: "4.00 Bad Request",
    129: "4.01 Unauthorized",
    130: "4.02 Bad Option",
    131: "4.03 Forbidden",
    132: "4.04 Not Found",
    133: "4.05 Method Not Allowed",
    134: "4.06 Not Acceptable",
    140: "4.12 Precondition Failed",
    141: "4.13 Request Entity Too Large",
    143: "4.15 Unsupported Content-Format",
    160: "5.00 Internal Server Error",
    161: "5.01 Not Implemented",
    162: "5.02 Bad Gateway",
    163: "5.03 Service Unavailable",
    164: "5.04 Gateway Timeout",
    165: "Proxying Not Supported"
}

coap_options = ({
    1: "If-Match",
    3: "Uri-Host",
    4: "ETag",
    5: "If-None-Match",
    7: "Uri-Port",
    8: "Location-Path",
    11: "Uri-Path",
    12: "Content-Format",
    14: "Max-Age",
    15: "Uri-Query",
    17: "Accept",
    20: "Location-Query",
    35: "Proxy-Uri",
    39: "Proxy-Scheme",
    60: "Size1"
},
    {
    "If-Match": 1,
    "Uri-Host": 3,
    "ETag": 4,
    "If-None-Match": 5,
    "Uri-Port": 7,
    "Location-Path": 8,
    "Uri-Path": 11,
    "Content-Format": 12,
    "Max-Age": 14,
    "Uri-Query": 15,
    "Accept": 17,
    "Location-Query": 20,
    "Proxy-Uri": 35,
    "Proxy-Scheme": 39,
    "Size1": 60
    }
)

dtls_version = {
    '0xfefd': 'DTLS v1.2'

}

dtls_content_type = {
    20: 'Change Cipher Spec',
    21: 'Encrypted Alert',
    22: 'Client Hello',
    23: 'Application Data'
}

dtls_client_hello = {
    1 : 'Client Hello',
    2 : 'Server Hello',
    3 : 'Hello Verify Request',
    14: 'Server Hello Done',
    16: 'Client Key Exchange',
    0 : 'Handshake'

}

dot15d4_fcf_frametype = {
    0: "Beacon",
    1: "Data",
    2: "Ack",
    3: "Command"
}

icmpv6_type = {
    155: 'RPL Control',
    128: 'Echo ping request',
    129: 'Echo ping reply'
}