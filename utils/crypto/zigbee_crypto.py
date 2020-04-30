from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *
from scapy.utils import conf, raw

# This package is very important to convert a string
# to a byte string with the format b'\xBB\xAA'
from binascii import unhexlify
from Cryptodome.Cipher import AES # Replaces Crypto module, since it doesn't have CCM_MODE, which is used later

conf.dot15d4_protocol="zigbee"

DOT154_CRYPT_ENC_MIC32 = 0x05

# Display
# For debug purpose
# class bcolors:
#     HEADER = '\033[95m'
#     OKBLUE = '\033[94m'
#     OKGREEN = '\033[92m'
#     WARNING = '\033[93m'
#     FAIL = '\033[91m'
#     ENDC = '\033[0m'
#     BOLD = '\033[1m'
#     UNDERLINE = '\033[4m'


def zigbee_decrypt(pktorig, key_net):
    """
    Decrypts Zigbee packets. Or at least, it should ....
    """
    doMicCheck = False

    #print("\n############################################################\n\n> Starting 4 parameters extraction")
    
    pkt = pktorig.copy()

    # Set key in byte format
    key = unhexlify(key_net)

    # 1. Get MIC using scapy black magic to rebuild the packet correctly
    pkt.nwk_seclevel = DOT154_CRYPT_ENC_MIC32
    pkt.data += pkt.mic
    pkt.mic = pkt.data[-4:]
    mic = pkt.mic
    pkt.data = pkt.data[:-4] # Reset pkt after MIC extracted

    # 2. Get ciphertext
    ciphertext = pkt[ZigbeeSecurityHeader].data

    # 3. Get nonce using two ways. The zbdecrypt way seems to be the right one. The second is another found on another project
    using_zb_nonce = True
    if using_zb_nonce:
        extended_src = pkt[ZigbeeSecurityHeader].source
        if extended_src is None:
            return None
        nonce = struct.pack('Q',*struct.unpack('>Q', extended_src.to_bytes(8, byteorder="big"))) + struct.pack('I', pkt[ZigbeeSecurityHeader].fc) + struct.pack('B', bytes(pkt[ZigbeeSecurityHeader])[0])
        # sys.byteorder MUST BE byteorder="big"
    else:
        # Get NONCE : create NONCE (for crypt) and zigbeeData (for MIC) according to packet type ----------> Whatever that means
        sec_ctrl_byte = str(pkt[ZigbeeSecurityHeader])[0]
        if ZigbeeAppDataPayload in pkt:
            nonce = str(struct.pack('L',pkt[ZigbeeNWK].ext_src))+str(struct.pack('I',pkt[ZigbeeSecurityHeader].fc)) + sec_ctrl_byte
        else:
            nonce = str(struct.pack('L',pkt[ZigbeeSecurityHeader].source))+str(struct.pack('I',pkt[ZigbeeSecurityHeader].fc)) + sec_ctrl_byte

    # 4. Get ZigbeeData, aka the content of the ZigbeeNWK header.
    data_len = len(ciphertext) + len(mic)
    if ZigbeeAppDataPayload in pkt:
        if data_len > 0:
            header = bytes(pkt[ZigbeeAppDataPayload])[:-data_len]
        else:
            header = bytes(pkt[ZigbeeAppDataPayload])
    else:
        if data_len > 0:
            header = bytes(pkt[ZigbeeNWK])[:-data_len]
        else:
            header = bytes(pkt[ZigbeeNWK])

    # # Print the 4 extracted parameters
    # For debug purpose
    
    # print(key)
    # hexdump(key)
    # print("\n--------------------\n\n" + bcolors.FAIL + "1. NONCE : ?????????? Most likely the cause of the issue. Length is good (13, function says 7 to 13) but probably bad content. Changing little/big endian doesn't correct the decryption.\n" + bcolors.ENDC)
    # print(f"Nonce : {nonce} ; Length : {len(nonce)}")

    # print("\n--------------------\n\n" + bcolors.OKGREEN + "2. MIC : validated\n" + bcolors.ENDC)
    # print(f"MIC : {pkt.mic} ; Length : {len(pkt.mic)}")

    # print("\n--------------------\n\n" + bcolors.WARNING + "3. Ciphertext : More or less validated. MIC isn't part of what's considered 'Ciphertext' which makes sense.\n" + bcolors.ENDC)
    # print(f"Ciphertext : {ciphertext} ; Length : {len(ciphertext)}")
    # hexdump(ciphertext)

    # print("\n--------------------\n\n" + bcolors.OKGREEN + "4. ZigbeeData : Validated (ends right before the part that is encrypted)\n" + bcolors.ENDC)
    # print(f"ZigbeeData : {header} ; Length : {len(header)}")
    # hexdump(header)


    ###########################
    # Decryption
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4) # Create cipher
    cipher.update(header) # ???? It doesn't change anything, but it was in the original code.
    payload = cipher.decrypt(ciphertext) # Decrypt the ciphertext
    
    # Verify MIC
    try:
        cipher.verify(mic)
        micCheck = True
    except ValueError:
        micCheck = False

    # print("\n\n############################################################\n" + bcolors.HEADER + "Decrypted packet :\n" + bcolors.ENDC)
    # hexdump(text)

    frametype = pkt[ZigbeeNWK].frametype
    if frametype == 0 and micCheck == 1:
        payload = ZigbeeAppDataPayload(payload)
    elif frametype == 1 and micCheck == 1:
        payload = ZigbeeNWKCommandPayload(payload)
    else:
        payload = raw(payload)

    if doMicCheck == False:
        return payload
    else:
        if micCheck == 1: return (payload, True)
        else:             return (payload, False)
            
