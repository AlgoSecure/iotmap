def hexstr_to_str(hex_str, fmt="little-endian"):
    str_res = ""
    
    if fmt == "big-endian":
        for i in range(int(len(hex_str)/2)):
            str_res += chr((int(hex_str[i*2 + 1], 16) *16 + int(hex_str[i*2 + 0], 16)))
    else: # little endian
        for i in range(int(len(hex_str)/2)):
            str_res += chr((int(hex_str[i*2 + 0], 16) *16 + int(hex_str[i*2 + 1], 16)))
    
    return str_res

def str_to_hexstr(base_str):
    # Little endian
    hex_res = ""
    for i in range(int(len(base_str))):
        hex_res += '{:02x}'.format(ord(base_str[i]))
    return hex_res

key = 'f247868f650fa30e2f0d5e1abc341179'
#key_net = hexstr_to_str(key)
key_net = key
