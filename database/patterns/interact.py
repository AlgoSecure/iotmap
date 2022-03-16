graph = 'application'
description = 'Represent interaction between nodes accoring to a time inspection'


# Create edges corresponding to the application communications
# Currently only support AS scheme
@classmethod
# def interact(cs, tx, delta):
def interact(cs, tx, delta):
    #delta = 1.5
    delta = delta

    # Select all nodes and edges (here represented by path p) that are involved 
    # in an actuator-sensor scheme.
    results = tx.run("""
    match p=(n:Node{label: 4})-[:TRANSEdge*1..]->(c: Node{label: 4})-[:TRANSEdge*1..]->(m:Node{label: 4})
    where 'source' in n.role and 'sink' in m.role and n <> m and 'controller' in c.role
    return p
    """)

    for result in results:
        nbRel = len(result["p"].relationships)
        rel = result["p"].relationships
        count = 1
        for i in range(1, nbRel):
            TX1 = rel[i - 1]['timestamp']
            TX2 = rel[i]['timestamp']
            for t2, t1 in ((tx2, tx1) for tx2 in TX2 for tx1 in TX1):
                if t2 > t1 and t2 - t1 < delta:
                    count += 1
                    break
                

        #logging.debug(f'Count: {count} and nbRel: {nbRel}')
        # All relationships are succeeded
        if count == nbRel:
            source, dest1 = rel[0].nodes
            dest1, sink = rel[-1].nodes
            
            tx.run("""
            match (n: Node{label: 5}), (m: Node{label: 5})
            where n.nameID = $nameIdn and m.nameID = $nameIdm
            Merge (n)-[: INTERACT {nwksrc: n.nwksrc, nwkdst: m.nwksrc}]->(m)
            """, nameIdn=source['nameID'], nameIdm=sink['nameID'])