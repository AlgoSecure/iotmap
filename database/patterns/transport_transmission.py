graph = 'transport'
description = 'Represent the data flow of bidirectionnal communications'

def transport_transmission_part1(cs, tx, delta):
    #delta = .6 # It is the time delta between a request and the response

    delta = delta
    
    # Get the source and destination nodes along with their
    # edges according to the apptype
    # results = tx.run("""
    # match ()-[r_g3:nwkLink]->()
    # match (n_src: Node {label: 'g3'}), (n_dst: Node {label: 'g3'})
    # where (r_g3.nwksrc in n_src.nwksrc) and r_g3.nwkdst in n_dst.nwksrc
    # with n_src, r_g3.nwksrc as nsrc , r_g3.nwkdst as mdst, r_g3.timestamp as tp order by tp
    # return n_src.nameID, nsrc, mdst, collect(distinct tp)
    # """).values()

    results = tx.run("""
    match ()-[r_g3:nwkLink]->()
    match (n_src: Node {label: 3}), (n_dst: Node {label: 3})
    where (r_g3.nwksrc in n_src.nwksrc) and r_g3.nwkdst in n_dst.nwksrc
    with n_src.nameID as srcID, n_dst.nameID as dstID, r_g3.nwksrc as nsrc , r_g3.nwkdst as mdst, r_g3.timestamp as tp order by tp
    return srcID, nsrc, dstID, mdst, collect(distinct tp)
    """).values()

    transNodes = {}
    dstNodes = {}
    label=4
    
    for line in results:
        srcID, srcN, dstID, dstN, txG = line
        dstNodes = {
            dstID: txG
        }
        if srcID in transNodes.keys():
            transNodes[srcID].update(dstNodes)
        else:
            transNodes[srcID] = dstNodes
            transNodes[srcID]['id'] = srcID
            transNodes[srcID]['role'] = []

    # logging.debug(transNodes)
            
    toreturn = []
    toprint = ""

    for src in transNodes.keys():
        for dst in transNodes[src].keys():
            if 'role' == dst or 'id' == dst:
                continue

            # Communication are only one-way
            source = src
            sink = dst
            
            # Dst only received so Dst is a sink
            # And so we are a one way communication
            if not dst in transNodes.keys():
                if 'source' not in transNodes[src]['role']:
                    transNodes[src]['role'].append('source')
                srcRole = list(set(transNodes[src]['role']))
                dstRole = ['sink']
                tx.run("""
                match (n: Node{label: $label}), (m: Node{label: $label})
                where $srcID = n.nameID and $dstID = m.nameID
                merge (n)-[: TRANSEdge {nwksrc: n.nwksrc, nwkdst: m.nwksrc, timestamp: $ts}]->(m)
                on create set n.role = n.role + $srcRole, m.role = m.role + $dstRole
                """, label=label, srcID=source, dstID=sink, srcRole=srcRole, dstRole=dstRole, ts=transNodes[source][sink])

            # here we have a one-way communication src to dst
            elif src not in transNodes[dst].keys():
                if 'source' not in transNodes[src]['role']:
                    transNodes[src]['role'].append('source')
                if 'sink' not in transNodes[dst]['role']:
                    transNodes[dst]['role'].append('sink')
                    
                srcRole = list(set(transNodes[src]['role']))
                dstRole = list(set(transNodes[dst]['role']))
                tx.run("""
                match (n: Node{label: $label}), (m: Node{label: $label})
                where $srcID = n.nameID and $dstID = m.nameID
                merge (n)-[: TRANSEdge {nwksrc: n.nwksrc, nwkdst: m.nwksrc, timestamp: $ts}]->(m)
                on create set n.role = $srcRole, m.role = $dstRole
                """, label=label, srcID=source, dstID=sink, srcRole = srcRole, dstRole = dstRole, ts=transNodes[source][sink])

            # bidirectional communications
            else:
                tx1 = transNodes[src][dst]
                tx2 = transNodes[dst][src]

                lentx1 = len(tx1)
                lentx2 = len(tx2)
                
                #j = 0
                for t2 in tx2:
                    #for i in range(j, lentx1):
                    for t1 in tx1:
                        #t1 = tx1[i]
                        if t2 > t1 :
                            if t2 - t1 < delta:

                                #logging.debug(f'TRANSEdge created: {dst} -> {src} with {t2} - {t1}')

                                toreturn.append([[str(dst)], [str(t2)], [str(src)], [str(t1)]])
                                toprint+=f"[{dst}], [{t2}], [{src}], [{t1}]\n"
                                
                                if 'source' not in transNodes[dst]['role']:
                                    transNodes[dst]['role'].append('source')
                                if 'sink' not in transNodes[src]['role']:
                                    transNodes[src]['role'].append('sink')
                                source = dst
                                sink = src
                                srcRole = list(set(transNodes[source]['role']))
                                dstRole = list(set(transNodes[sink]['role']))
                                tx.run("""
                                match (n: Node{label: $label}), (m: Node{label: $label})
                                where $srcID = n.nameID and $dstID = m.nameID
                                merge (n)-[: TRANSEdge {timestamp: $ts, nwksrc: n.nwksrc, nwkdst: m.nwksrc}]->(m)
                                on create set n.role=$srcRole, m.role=$dstRole
                                """, label=label, srcID=source, dstID=sink, srcRole=srcRole, dstRole=dstRole, ts=tx2)
                                #j = i
                                #break
                        else:
                            continue

    with open("tests/eval-theta.txt", 'w') as outputFile:
        outputFile.write(f"{toprint}")

    return toreturn

def transport_transmission_part2(cs, tx, delta):
    #Let's create controller
    results = tx.run("""
    match (n: Node{label: 4})-[r1]->(m: Node{label: 4})-[r2]->(d: Node{label: 4})
    where ('source' in n.role or 'controller' in n.role) and ('source' in m.role and 'sink' in m.role) and ('sink' in d.role or 'controller' in d.role) and n <> d
    with r1.nwksrc as src, n.nameID as nid, r1.nwkdst as ctrl, m.nameID as mid, r2.nwkdst as sink, d.nameID as did, r1.timestamp as ts1, r2.timestamp as ts2
    return src, nid, ctrl, mid, sink, did, ts1, ts2
    """).values()

    #delta2 = .7
    delta = delta

    toreturn = []
    toprint = ""

    for line in results:
        source, sid, controller, cid, sink, did, ts1, ts2 = line

        if isinstance(controller, list):
            controller = controller[0]      
        
        for t2 in ts2:
            for t1 in ts1:
            # we get a controller
                if t2 > t1 and t2 - t1 < delta:

                    
                    toreturn.append([[str(sid)], [str(t1)], [str(cid)], [str(t2)], [str(did)]])
                    toprint+=f"[{sid}], [{t1}], [{cid}], [{t2}], [{did}]\n"
                    
                    tx.run("""
                    match (n: Node{label: 4})
                    where $ctrl in n.nwksrc
                    set n.role = ['controller']
                    """, ctrl=controller)

    with open("tests/controller-legit.txt", 'w') as outputFile:
        outputFile.write(f"{toprint}")

    return toreturn

@classmethod
def transport_transmission(cs, tx, delta, delta2=None):
    pbc = classmethod(transport_transmission_part1(cs, tx, delta))
    ret = None
    if not delta2 is None:
        ret = classmethod(transport_transmission_part2(cs, tx, delta2))

    return pbc, ret