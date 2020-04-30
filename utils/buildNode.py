def sixlownpanNode(dlAddress):
	node = []
	dl = dlAddress
	nwkprefix = ["::2", "fd00::2"]
	nwk = ""
	if len(dl) == 23: # 00:12:4b:00:12:04:ce:a4
		dl += ';' + dl[3:-3]
		for prefix in nwkprefix:
			sufix = ''
			for i in range(6, len(a), 6):
				sufix += dl[i:i+5].replace(':', '') + ':'
			nwk += prefix + dl[3:5] + suffix[-1] + ';'

		dlAddress = dlAddress[:-3]

	nwk += 'fe80::2' + dlAddress[3:]
	node.append(dl, nwk)
	return node

def zigbeeNode(dlAddress):
	return [dlAddress, dlAddress]

def btleNode(dlAddress):
	return [dlAddress, dlAddress]

# Dictionnary used by the wrapper to call the protocol-specific function
functions = {
	'btle': btleNode,
	'sixlowpan': sixlownpanNode,
	'zigbee': zigbeeNode
}

# Wrapper that calls the protrocol-specific function 
# to create the node based on the dl address
def createNode(protocol, dlAddress):
	return function[protocol](dlAddress)
