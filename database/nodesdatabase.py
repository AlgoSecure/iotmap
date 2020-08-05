from neo4j import GraphDatabase
import sys
import os.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
from scapy.utils import hexdump

class NodesDatabase(object):
    def __init__(self, uri, user, password):
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
                
    def close(self):
        self._driver.close()

    # Delete all nodes
    @classmethod
    def delete_nodes(cls, tx, label):
        tx.run("""
        MATCH (n: Node)
        where n.label >= $label
        optional match (n)-[r]-()
        delete r, n""", label=label
        )
        
    @classmethod
    def delete_transmissions(cls, tx, label):
        tx.run("""
        MATCH (n: Node)
        where n.label >= $label
        optional match (n)-[r]-()
        delete r""", label=label
        )

    # Delete all visual nodes 
    @classmethod
    def delete_visu_nodes(cls, tx, label):
        if label > 3:
            return None
        
        if label == 2:
            tx.run("""
            MATCH (n: Node)
            where n.label = 'l2'
            optional match (n)-[r]-()
            delete r, n"""
            )

        tx.run("""
        MATCH (n: Node)
        where n.label = 'l3'
        optional match (n)-[r]-()
        delete r, n"""
        )

    # Create a node with its properties
    @classmethod
    def create_node(cls, tx, node):
        nameID, dlsrc, nwksrc, label, role = node
        tx.run('''
            merge (n: Node {label: $label, nameID: $nameID, dlsrc: $dlsrc, nwksrc: $nwksrc, role:$role})
        ''', label=label, nameID=nameID, dlsrc=dlsrc, nwksrc=nwksrc, role=role)

    # Duplicate all nodes that is useful to create independant graph
    # for each layer.
    @classmethod
    def duplicate_node(cls, tx, label_src, label_dst):
         tx.run("""
         match (n:Node {label: $label_src}) 
         with n as map 
         create (copy:Node {label: $label_dst}) 
         set copy.nameID = map.nameID, copy.dlsrc = map.dlsrc, copy.nwksrc = map.nwksrc, copy.neighbors = map.neighbors, copy.role = map.role
         """, label_src=label_src, label_dst=label_dst
         )
    

    # This function allows a better insight of the link between nodes at layer 2
    @classmethod
    def node_visu_dllink(cls, tx, label):
        tx.run("""
        match ()-[r: dlLink]->() 
        match (n_src: Node {label: $label}), (n_dst: Node {label: $label}) 
        where (r.dlsrc in n_src.dlsrc) and r.dldst in n_dst.dlsrc
        merge (n_src)-[:layer2]->(n_dst)""", label=label)

    # Simpler view of the nwk graph where only one edge is drew between
    # two nodes
    @classmethod
    def node_visu_nwklink(cls, tx, label):
        tx.run("match ()-[r:nwkLink]->() "
               "match (n_src: Node {label: $label}), (n_dst: Node {label: $label}) "
               "where (r.nwksrc in n_src.nwksrc) and r.nwkdst in n_dst.nwksrc "
               "merge (n_src)-[:layer3]->(n_dst)",
               label=label
        )

    # Simpler view of the trans graph where only one type of application is
    # displayed
    @classmethod
    def node_visu_translink(cls, tx):
        tx.run("""
        match (n)-[rl3: layer3]->(m)
        match (n2: Node{label:'5'})-[r]->(m2: Node{label:'5'}) 
        where n2.nwksrc in n.nwksrc and m2.nwksrc in m.nwksrc
        merge (n)-[:type(r)]->(m)
        with rl3
        delete rl3
        """)

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

    # Create edges corresponding to the network communications
    @classmethod
    def nwk_transmission(cls, tx, label):  
        tx.run("match ()-[r_g2:dlLink]->() "
               "match (n_src: Node {label: $label}), (n_dst: Node {label: $label}) "
               "where (r_g2.dlsrc in n_src.dlsrc and r_g2.nwksrc in n_src.nwksrc) and r_g2.nwkdst in n_dst.nwksrc "
               "create (n_src)-[r:nwkLink { timestamp: r_g2.timestamp, dlsrc: r_g2.dlsrc, dldst: r_g2.dldst, nwksrc: r_g2.nwksrc, nwkdst: r_g2.nwkdst, apptype: r_g2.apptype, data: r_g2.data} ]->(n_dst)",
               label=label
        )

    @classmethod
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

    @classmethod
    def transport_transmission_part2(cs, tx, delta):
        #Let's create controller
        results = tx.run("""
        match (n: Node{label: 4})-[r1]-(m: Node{label: 4})-[r2]-(d: Node{label: 4})
        where ('source' in n.role or 'controller' in n.role) and ('source' in m.role and 'sink' in m.role) and ('sink' in d.role or 'controller' in d.role) and n <> d
        with r1.nwksrc as src, r1.nwkdst as ctrl, r2.nwkdst as sink, r1.timestamp as ts1, r2.timestamp as ts2
        return src, ctrl, sink, ts1, ts2
        """).values()

        #delta2 = .7
        delta = delta

        toreturn = []
        toprint = ""

        for line in results:
            source, controller, sink, ts1, ts2 = line

            if isinstance(controller, list):
                controller = controller[0]      
            
            for t2 in ts2:
                for t1 in ts1:
                # we get a controller
                    if t2 > t1 and t2 - t1 < delta:

                        
                        toreturn.append([source, [str(t1)], [controller], [str(t2)], sink])
                        toprint+=f"{source}, [{t1}], [{controller}], [{t2}], {sink}\n"
                        
                        tx.run("""
                        match (n: Node{label: 4})
                        where $ctrl in n.nwksrc
                        set n.role = ['controller']
                        """, ctrl=controller)
    
        with open("tests/controller-legit.txt", 'w') as outputFile:
            outputFile.write(f"{toprint}")

        return toreturn
    # Create edges corresponding to the application communications
    # Currently only support AS scheme
    @classmethod
    def application_transmission(cs, tx, delta):
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


    ####
    ###  Following functions are wrappers called by the databaseController 
    ####

    # Call the trans_transmission_part{1,2} function to store all the communications
    # between nodes
    def transGraph(self, delta, delta2=None):
        ret = None
        with self._driver.session() as session:
            session.write_transaction(self.duplicate_node, 2, 4)
            session.write_transaction(self.transport_transmission_part1, delta)
            if not delta2 is None:
                ret = session.write_transaction(self.transport_transmission_part2, delta2)

            return ret

    # Call the trans_transmission function to store all the communications
    # between nodes
    def appGraph(self, delta):
        with self._driver.session() as session:
            session.write_transaction(self.duplicate_node, 4, 5)
            session.write_transaction(self.application_transmission, delta)

    # Call the nwk_transmission function to store all the communications
    # between nodes
    def nwkGraph(self):
        with self._driver.session() as session:
            session.write_transaction(self.duplicate_node, 2, 3)
            session.write_transaction(self.nwk_transmission, 3)

            session.write_transaction(self.node_visu_nwklink, 'l2')

    # Call the node_transmission function to store all the communications
    # between nodes
    def create_nodesTX(self, nodesTX):
        with self._driver.session() as session:
            for t in nodesTX:
                session.write_transaction(self.node_transmission, nodesTX[t])

            session.write_transaction(self.duplicate_node, 2, 'l2')
            session.write_transaction(self.node_visu_dllink, 'l2')

    # Handle the creation of multiple nodes
    # using the neo4j syntax
    def create_nodes(self, nodes):
        with self._driver.session() as session:
            for n in nodes:
                session.write_transaction(self.create_node, n)

    def del_nodes(self, label, mode):
        with self._driver.session() as session:
            if 'node' in mode:
                session.write_transaction(self.delete_nodes, label)
            else:
                session.write_transaction(self.delete_visu_nodes, label)

    def getResults(self):
        values = ''  
        with self._driver.session() as session:
            values = session.run("""
                match (n)-[r]-(m)
                where n.nwksrc = r.nwksrc and n.label >=4
                return n.nwksrc, n.role, m.nwksrc, m.role, type(r)
             """).values()
        return values

    def getNodes(self):
        with self._driver.session() as session:
            nodes = session.run("""
                MATCH (n:Node)
                where n.label = 2
                with n.nameID as id, n.nwksrc as nwk, n.dlsrc as dl 
                return id, dl, nwk""").values()
        return nodes 


    def getNode(self, nodeID):
        with self._driver.session() as session:
            node = session.run("""
                MATCH (n:Node)
                where n.nameID = $nodeID
                with n.nameID as id, n.dlsrc as dl, n.nwksrc as nwk
                return id, dl, nwk
                """, nodeID = nodeID).values()

        return node[0]

    def maxID(self):
        with self._driver.session() as session:
            maxID = session.run("""
                MATCH (n:Node) RETURN MAX(n.nameID)
                """).values()

        return maxID[0]

    def removeTX(self, label):
        with self._driver.session() as session:
            session.write_transaction(self.delete_transmissions, label)
        
    def removeNode(self, nodeID):
        with self._driver.session() as session:
            ret = session.run("""
                MATCH (n:Node)
                where n.nameID = $nodeID
                delete n
                """, nodeID = nodeID).values()

        return ret
