from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from .bleConstants import *

from bluefruit_sniffer import *

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
        # We also support the nordic format
        if not BTLE_RF in pkt:
            pkt = NordicBLE(bytes_encode(pkt))

        layers['src'] = 'Master'
        layers['dst'] = 'Slave'

        layers['RFlayer'] = self.extract_pkt_rflayer(pkt)

        layers['layer2'] = self.extract_pkt_layer2(pkt)

        # A ctrlPDU packet contains no more layers
        if hasattr(layers, 'ctrlPDU') or len(pkt.layers()) == 4:
            return layers

        # Currently I don't know if it exists another type of packet that
        # does not contain more layers
        if L2CAP_Hdr in pkt:
            layers['layer3'] = self.extract_pkt_layer3(pkt)

            check_response = False
            
            if (layers['layer3']['cid'] != 2720 or \
                layers['layer3']['cid'] != 'L2CAP Fragement'):
                layers['layer4'] = self.extract_pkt_layer4(pkt)

                if layers['layer4'] != {}:
                    if layers['RFlayer']['direction'] != -1:
                        if layers['RFlayer']['direction'] == 'SM':
                            layers['src'] = 'Slave'
                            layers['dst'] = 'Master'

                    else:
                        if self.verbose:
                            if 'Response' in layers['layer4']['opcode'] or \
                               'Handle' in layers['layer4']['opcode']:
                                check_response = True
                        else:
                            check_response = layers['layer4']['opcode'] in [0x09, 0x0b, 0x1d]
                            
                        if check_response is True:
                            layers['src'], layers['dst'] = layers['dst'], layers['src']
                else:
                    if layers['RFlayer']['direction'] != -1:
                        if layers['RFlayer']['direction'] == 'SM':
                            layers['src'] = 'Slave'
                            layers['dst'] = 'Master'                        
        return layers
            
    def extract_pkt_rflayer(self, pkt):
        """
        Extracts BTLE specific information from radio frequence
        Called by extract_pkt_info(). 
        This layer contains the physical layer of BLE
        """
        rfFields = {}
        if BTLE_RF in pkt:
            rfFields["rf_channel"] = pkt.rf_channel
            rfFields["signal"] = pkt.signal
            rfFields["noise"] = pkt.noise
            rfFields["flags"] = getFlags(pkt.flags.value) if self.verbose else pkt.flags.value
            rfFields["access_address_offenses"] = pkt.access_address_offenses
            rfFields["reference_access_address"] = pkt.reference_access_address
            rfFields["direction"] = -1
        
        else:
            rfFields["rf_channel"] = pkt.channel
            rfFields["signal"] = 0
            rfFields["noise"] = 0
            rfFields["flags"] = pkt.flags
            rfFields["access_address_offenses"] = -1
            rfFields["reference_access_address"] = -1
            rfFields["direction"] = getDirection(pkt.flags) if self.verbose else pkt.flags & 2

        return rfFields

    def extract_pkt_layer2(self, pkt):
        """
        Extracts BT4LE specific information from header to update node/transmission state
        Called by extract_pkt_info(). 
        This layer contains BTLE, BTLE_DATA and if exist CtrlPDU 
        """
        dataheader, layer2 = {}, {}
        haveCtrlPDU = False
        isConnectReq = False
        
        if BTLE_RF in pkt:
            layer2['access_addr'] = hex(pkt.access_addr)
            layer2['crc'] = hex(pkt.crc)

        if BLE_LL in pkt:
            st = hex(pkt.access)[2:] # On supprime le 0x
            AA = "".join([st[x:x+2] for x in range(0,len(st),2)][::-1])
            AA = "0x" + AA
            layer2['access_addr'] = AA

        if BLE_LL_Adv in pkt:
            connpkt = BTLE(bytes_encode(pkt.getlayer(BLE_LL))[:-3])
            if BTLE_CONNECT_REQ in connpkt:
                isConnectReq = True


        if BTLE_ADV in pkt or isConnectReq:
            if not isConnectReq:
                connpkt = pkt

            dataheader['RxAdd'] = RxTxAdd[connpkt.RxAdd] if self.verbose == 1 else connpkt.RxAdd
            dataheader['TxAdd'] = RxTxAdd[connpkt.TxAdd] if self.verbose == 1 else connpkt.TxAdd
            dataheader['RFU'] = connpkt.RFU
            dataheader['PDU_type'] = PDUType[connpkt.PDU_type] if self.verbose == 1 else connpkt.PDU_type
            dataheader['Length'] = hex(connpkt.Length)

        if BTLE_CONNECT_REQ in pkt or isConnectReq:
            if not isConnectReq:
                connpkt = pkt

            dataheader['Master'] = connpkt.InitA
            dataheader['Slave'] = connpkt.AdvA
            #dataheader['AA'] = pkt.AA
            layer2['access_addr'] = hex(connpkt.AA)
            layer2['crc'] = hex(connpkt.crc_init)
            dataheader['win_size'] = hex(connpkt.win_size)
            dataheader['win_offset'] = hex(connpkt.win_offset)
            dataheader['interval'] = hex(connpkt.interval)
            dataheader['channelMap'] = hex(connpkt.chM)
            dataheader['hop'] = connpkt.hop

        if BTLE_DATA in pkt:
            dataheader['RFU'] = pkt.RFU
            dataheader['LLID'] = LLID[pkt.LLID] if self.verbose == 1 else pkt.LLID
            dataheader['MD'] = pkt.MD
            dataheader['SN'] = pkt.SN
            dataheader['len'] = pkt.len

        if BLE_LL_Data in pkt:
            dataheader['RFU'] = pkt.rfu
            dataheader['LLID'] = LLID[pkt.llid] if self.verbose == 1 else pkt.llid
            dataheader['MD'] = pkt.moar_data
            dataheader['SN'] = pkt.seqn
            dataheader['len'] = pkt.length

        
        layer2['data header'] = dataheader

        if NordicBLE in pkt and not BLE_LL_Adv in pkt and len(pkt.layers()) == 4:
            haveCtrlPDU = True
            ctrlpkt = pkt
            try:
                ctrlpkt = CtrlPDU(bytes_encode(pkt.load))
            except struct.error: 
                i = 1
                while (not CtrlPDU in ctrlpkt) and i <= 3:
                    ctrlpkt = CtrlPDU(bytes_encode(pkt.load)[:-i])
                    i += 1

        if CtrlPDU in pkt or haveCtrlPDU:
            if not haveCtrlPDU:
                ctrlpkt = pkt

            ctrlPDU = {
                'version': ctrlpkt.version,
                'company': ctrlpkt.Company,
                'subvers': ctrlpkt.subversion
            }

            if self.verbose == 1 and ctrlpkt.optcode in optCode.keys():
                ctrlPDU['optcode']: optCode[ctrlpkt.optcode]
            else:
                ctrlPDU['optcode'] = ctrlpkt.optcode

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
        }

        if self.verbose == 1 and l2capHdr.cid in CID.keys():
            layer3['cid'] = CID[l2capHdr.cid]
        else:
            layer3['cid'] = l2capHdr.cid # L2CAP Fragement

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
