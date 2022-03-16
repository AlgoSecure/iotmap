graph = 'datalink'
description = 'Represent point to point communications'

# Create edges corresponding to the data link communications
@classmethod
def node_transmission(cls, tx, properties):
    dlsrc, dldst = properties['dlsrc'], properties['dldst'] 
    tx.run( """
    match (n_src: Node {label: 2}) 
    where $dlsrc in n_src.dlsrc 
    match (n_dst: Node) 
    where $dldst in n_dst.dlsrc 
    create (n_src)-[:dlLink $properties]->(n_dst)""", 
    dlsrc=dlsrc, dldst = dldst, properties=properties)