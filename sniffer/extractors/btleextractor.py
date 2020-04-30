from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from .bleConstants import *

class BTLEextractor():
    """
    BTLE extractor. Extracts informations from BTLE packets. 
    Call extract_pkt_layers to get the packet informations in a list.
    """
    def __init__(self, args):
        self.index = 0
        self.verbose = args[0]

    
    def extract_pkt_layers(self, pkt):
        """
        Extracts all layers specific information from header.
        Returns [src, dst, transmission] list containing all relevant informations.
        """
        layers = {}
        layers['time'] = float(pkt.time)

        # This layer is only available if the pcap is in ll_phdr format
        if BTLE_RF in pkt:
            layers['RFlayer'] = self.extract_pkt_rflayer(pkt)
        
        layers['layer2'] = self.extract_pkt_layer2(pkt)

        # A ctrlPDU packet contains no more layers
        if hasattr(layers, 'ctrlPDU'):
            return layers

        # Currently I don't know if it exists another type of packet that
        # does not contain more layers
        if L2CAP_Hdr in pkt:
            layers['layer3'] = self.extract_pkt_layer3(pkt)

            check_response = False
            
            if (layers['layer3']['cid'] != 2720 or \
                layers['layer3']['cid'] != 'L2CAP Fragement'):
                layers['layer4'] = self.extract_pkt_layer4(pkt)
                layers['src'] = 'Master'
                layers['dst'] = 'Slave'

                if layers['layer4'] != {}:
                    if self.verbose:
                        if 'Response' in layers['layer4']['opcode'] or \
                           'Handle' in layers['layer4']['opcode']:
                            check_response = True
                    else:
                        check_response = layers['layer4']['opcode'] in [0x09, 0x0b, 0x1d]
                        
                    if check_response is True:
                        layers['src'], layers['dst'] = layers['dst'], layers['src']
                        
        return layers
            
    def extract_pkt_rflayer(self, pkt):
        """
        Extracts BT4LE specific information from radio frequence
        Called by extract_pkt_info(). 
        This layer contains BTLE_RF
        """

        rfFields = {}
        rfFields["rf_channel"] = pkt.rf_channel
        rfFields["signal"] = pkt.signal
        rfFields["noise"] = pkt.noise
        rfFields["flags"] = getFlags(pkt.flags.value) if self.verbose else pkt.flags.value
        rfFields["access_address_offenses"] = pkt.access_address_offenses
        rfFields["reference_access_address"] = pkt.reference_access_address
        
        return rfFields

    def extract_pkt_layer2(self, pkt):
        """
        Extracts BT4LE specific information from header to update node/transmission state
        Called by extract_pkt_info(). 
        This layer contains BTLE, BTLE_DATA and if exist CtrlPDU 
        """
        dataheader, layer2 = {}, {}
        layer2['access_addr'] = hex(pkt.access_addr)
        layer2['crc'] = hex(pkt.crc)
        
        if BTLE_ADV in pkt:
            dataheader['RxAdd'] = RxTxAdd[pkt.RxAdd] if self.verbose == 1 else pkt.RxAdd
            dataheader['TxAdd'] = RxTxAdd[pkt.TxAdd] if self.verbose == 1 else pkt.TxAdd
            dataheader['RFU'] = pkt.RFU
            dataheader['TxAdd'] = PDUType[pkt.PDU_type] if self.verbose == 1 else pkt.PDU_type
            dataheader['Length'] = hex(pkt.Length)

        if BTLE_CONNECT_REQ in pkt:
            dataheader['Master'] = pkt.InitA
            dataheader['Slave'] = pkt.AdvA
            #dataheader['AA'] = pkt.AA
            layer2['access_addr'] = hex(pkt.AA)
            layer2['crc'] = hex(pkt.crc_init)
            dataheader['win_size'] = hex(pkt.win_size)
            dataheader['win_offset'] = hex(pkt.win_offset)
            dataheader['interval'] = hex(pkt.interval)
            dataheader['channelMap'] = hex(pkt.chM)
            dataheader['hop'] = pkt.hop

        if BTLE_DATA in pkt:
            dataheader['RFU'] = pkt.RFU
            dataheader['LLID'] = LLID[pkt.LLID] if self.verbose == 1 else pkt.LLID
            dataheader['MD'] = pkt.MD
            dataheader['SN'] = pkt.SN
            dataheader['len'] = pkt.len
        
        layer2['data header'] = dataheader

        if CtrlPDU in pkt:
            ctrlPDU = {
                'optcode': optCode[pkt.optcode] if self.verbose == 1 else pkt.optcode,
                'version': pkt.version,
                'company': pkt.Company,
                'subvers': pkt.subversion
            }

            layer2['ctrlPDU'] = ctrlPDU

        return layer2

    def extract_pkt_layer3(self, pkt):
        """
        Extracts BT4LE specific information from L2CAP layer
        Called by extract_pkt_info(). 
        """
        l2capHdr = pkt.getlayer(L2CAP_Hdr)
        layer3 = {
            'len': l2capHdr.len,
            'cid': CID[l2capHdr.cid] if self.verbose else l2capHdr.cid
        }

        return layer3

    def extract_pkt_layer4(self, pkt):
        """
        Extracts BT4LE specific information from ATT layer
        Called by extract_pkt_info(). 
        """
        layer4 = {}
        if hasattr(pkt, 'opcode'):
            layer4 = {
                'opcode': opCode[pkt.opcode] if self.verbose else pkt.opcode,
                'gatt_handle': '' if pkt.opcode != 0x0a else hex(pkt.gatt_handle),
                'start': '' if pkt.opcode != 0x08 else hex(pkt.start),
                'end': '' if pkt.opcode != 0x08 else hex(pkt.end),
                'uuid': '' if pkt.opcode != 0x08 else hex(pkt.uuid),
                'len': '' if pkt.opcode != 0x09 else hex(pkt[4].len),
                'handles': '' if pkt.opcode != 0x09 else [getHandles(h, self.verbose) for h in pkt.handles],
                'request': '' if pkt.opcode != 0x01 else hex(pkt.request),
                'handle': '' if pkt.opcode != 0x01 else hex(pkt.handle),
                'ecode': '' if pkt.opcode != 0x01 else hex(pkt.ecode),
                'value': '' if pkt.opcode != 0x0b else pkt.value.hex()
            }

        return layer4
