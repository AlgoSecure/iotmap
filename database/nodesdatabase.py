from neo4j import GraphDatabase
import sys
import os.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
from scapy.utils import hexdump

from utils.utils import addpatterns

@addpatterns
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
         merge (copy:Node {label: $label_dst, nameID: map.nameID, dlsrc: map.dlsrc, nwksrc: map.nwksrc, role: map.role})
         """, label_src=label_src, label_dst=label_dst
         # set copy.nameID = map.nameID, copy.dlsrc = map.dlsrc, copy.nwksrc = map.nwksrc, copy.neighbors = map.neighbors, copy.role = map.role
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

    ####
    ###  Following functions are wrappers called by the databaseController 
    ####

    # Call the trans_transmission_part{1,2} function to store all the communications
    # between nodes
    def transGraph(self, pattern, delta, delta2=None):
        
        if not pattern in self._graph_patterns['transport'].keys():
            print(f"""[e] - The pattern {pattern} is not available to build the transport graph. 
Please select an existing pattern.""")
            return 

        func = getattr(self, pattern, pattern)

        with self._driver.session() as session:
            session.write_transaction(self.duplicate_node, 2, 4)
            pbc, ret = session.write_transaction(func, delta, delta2)

            return pbc, ret

    # Call the trans_transmission function to store all the communications
    # between nodes
    def appGraph(self, pattern, delta):

        if not pattern in self._graph_patterns['application'].keys():
            print(f"""[e] - The pattern {pattern} is not available to build the application graph. 
Please select an existing pattern.""")
            return 

        func = getattr(self, pattern, pattern)

        with self._driver.session() as session:
            session.write_transaction(self.duplicate_node, 4, 5)
            session.write_transaction(func, delta)

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

    def getRoutingFrames(self, source, router, dest, delta):
        with self._driver.session() as session:
            results = session.run("""
                match (n:Node{label: 2, nameID: $source})-[r1:dlLink]->(c:Node{nameID: $router, label: 2})-[r2:dlLink]->(m:Node{label: 2, nameID: $dest})
                where n <> m and r2.timestamp > r1.timestamp and r2.timestamp - r1.timestamp < $delta
                return n.nwksrc, r1.timestamp, c.nwksrc, r2.timestamp, m.nwksrc
                """, source=source, dest=dest, router=router, delta=delta).values()
        return results


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
