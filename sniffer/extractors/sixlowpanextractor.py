from scapy.utils import *
from scapy.layers.dot15d4 import *
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
        # Get key from utils2 if key unset but decryption wanted

    # need some improvements in the futur
    def extract_pkt_layers(self, pkt):
        """
        Extracts all layers specific information from header.
        Returns [src, dst, transmission] list containing all relevant informations.
        """
        layers = {}
        layers['time'] = float(pkt.time)

        if not CoAP in pkt:
            return None
        
        layers['layer2'] = {
            'src_addr': hex_to_string(hex(pkt.src_addr)),
            'dst_addr': hex_to_string(hex(pkt.dest_addr)),
            'dest_panid': hex(pkt.dest_panid)
        }

        layers['layer3'] = {
            'src': pkt.src,
            'dst': pkt.dst
        }

        layers['layer4'] = {
            'code': coap_codes[pkt.code] if self.verbose else pkt.code
        }

        if pkt.code == 69:
            try:
                layers['layer4']['value'] = pkt.load.decode('utf-8') if hasattr(pkt, 'load') else 'Done'
            except:
                print("Timestamp : " + str(pkt.time))
                return None
            
                
        return layers

    

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
    coapPkts = []
    MID = []
    
    for x in pkts:
        if CoAP in x and (x.code==1 or x.code==2 or x.code==69):
            coapPkts.append(x)
            MID.append(x.msg_id)

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
        
    return f_pkts

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
