graph = 'network'
description = 'Represent end to end communications'

# Create edges corresponding to the network communications
@classmethod
def nwk_transmission(cls, tx, label):  
	tx.run("""match ()-[r_g2:dlLink]->()
		match (n_src: Node {label: $label}), (n_dst: Node {label: $label})
		where (r_g2.dlsrc in n_src.dlsrc and r_g2.nwksrc in n_src.nwksrc) and r_g2.nwkdst in n_dst.nwksrc
		create (n_src)-[r:nwkLink { timestamp: r_g2.timestamp, dlsrc: r_g2.dlsrc, dldst: r_g2.dldst, nwksrc: r_g2.nwksrc, nwkdst: r_g2.nwkdst, apptype: r_g2.apptype, data: r_g2.data} ]->(n_dst)""",
		label=label
	)