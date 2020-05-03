# Getting started

This document is a walkthrough to use IoTMap with an example.

## Requirements :

See [requirements in main documentaion](../README.md#requirements-)

## Installation 

See [installation in main documentaion](../README.md#installation)

## Configure the database

As explained in the [README](../README.md) file, the first thing before using IoTMap is to configure the database to be sure IoTMap can use it. 
So, we start the database with the following command:
```
./database/neo4j-community/bin/neo4j start
```

After few minutes, the web interface is accessible through http://localhost:7474. 

![neo4j first start](images/neo4j-first-start.PNG)

Initial credentials are neo4j/neo4j, then a new password is requested. 
The simplest is to set **iotmap** as password. For a different value, see how to
update the code [in the main documentation](../README.md#use-custom-credentials).

## First run of IoTMap

The `test` folder contains any examples files to start with IoTMap. 
We will use them as demonstration on how to use IoTMap.

### Populate the database

IoTMap displays the following prompt command when started:
```
$ python3 iotmap.py
Starting the database
Database is available at http://localhost:7474/



IIIIIIIIII              TTTTTTTTTTTTTTTTTTTTTTTMMMMMMMM               MMMMMMMM
I::::::::I              T:::::::::::::::::::::TM:::::::M             M:::::::M
I::::::::I              T:::::::::::::::::::::TM::::::::M           M::::::::M
II::::::II              T:::::TT:::::::TT:::::TM:::::::::M         M:::::::::M
  I::::I     oooooooooooTTTTTT  T:::::T  TTTTTTM::::::::::M       M::::::::::M  aaaaaaaaaaaaa  ppppp   ppppppppp
  I::::I   oo:::::::::::oo      T:::::T        M:::::::::::M     M:::::::::::M  a::::::::::::a p::::ppp:::::::::p
  I::::I  o:::::::::::::::o     T:::::T        M:::::::M::::M   M::::M:::::::M  aaaaaaaaa:::::ap:::::::::::::::::p
  I::::I  o:::::ooooo:::::o     T:::::T        M::::::M M::::M M::::M M::::::M           a::::app::::::ppppp::::::p
  I::::I  o::::o     o::::o     T:::::T        M::::::M  M::::M::::M  M::::::M    aaaaaaa:::::a p:::::p     p:::::p
  I::::I  o::::o     o::::o     T:::::T        M::::::M   M:::::::M   M::::::M  aa::::::::::::a p:::::p     p:::::p
  I::::I  o::::o     o::::o     T:::::T        M::::::M    M:::::M    M::::::M a::::aaaa::::::a p:::::p     p:::::p
  I::::I  o::::o     o::::o     T:::::T        M::::::M     MMMMM     M::::::Ma::::a    a:::::a p:::::p    p::::::p
II::::::IIo:::::ooooo:::::o   TT:::::::TT      M::::::M               M::::::Ma::::a    a:::::a p:::::ppppp:::::::p
I::::::::Io:::::::::::::::o   T:::::::::T      M::::::M               M::::::Ma:::::aaaa::::::a p::::::::::::::::p
I::::::::I oo:::::::::::oo    T:::::::::T      M::::::M               M::::::M a::::::::::aa:::ap::::::::::::::pp
IIIIIIIIII   ooooooooooo      TTTTTTTTTTT      MMMMMMMM               MMMMMMMM  aaaaaaaaaa  aaaap::::::pppppppp
                                                                                                p:::::p
                                                                                                p:::::p
                                                                                               p:::::::p
                                                                                               p:::::::p
                                                                                               p:::::::p
                                                                                               ppppppppp


                                Version=0.1

IoTMap > help

Core commands
=============

 Commands   Description
--------------------------------
 database   Use database mode.
 sniffing   Use sniffing mode.
 exploit    Use exploit mode.
 modelling  Use modelling mode.


IoTMap >
```
Te `help` command shows IoTMap has four main modules: **database, sniffing, exploit and modelling**. 
Exploit and sniffing modules are still work in progress and will not be introduced in this walkthrough.

As it is the first run of IoTMap, we need to populate the database to generate a modelling. 
To do so, start the **database** module:

```
IoTMap > database
IoTMap database > help

Core commands
=============

 Commands   Description
--------------------------------
 database   Use database mode.
 sniffing   Use sniffing mode.
 exploit    Use exploit mode.
 modelling  Use modelling mode.


Database commands
=================

        Interact with the neo4j database.

List of available commands :
        addNodes
        clearDatabase
        exportDB
        getNodes
        help
        importDB
        importPcaps
        mergeNodes
        removeNode

For more information about any commands hit :
        <command name> -h

IoTMap database > 
```

Many commands are available. To populate the database, use either `importDB` or `importPCAPS`, 
depending on how you want to populate the database. 
This example will use `importPCAPS`. 

For each command, a help menu is available using `-h`:
```
IoTMap database > importPcaps -h
Import pcap files into the database

        Usage: importPcaps (<protocol> <pcap>)... [--output <filename>] [--thread <nbThread>] [--nodesFile <nodesFile>]

        Options:
            -h, --help                   Print this message.
            -o, --output <filename>      Output file to store the result.
            -t, --thread <nbThread>      Thread number to use [default: 1].
            -n, --nodesFile <nodesFile>  File that contains a list of nodes used in communications.

        Arguments:
            protocol                   Name of the IoT protocol.
            pcap                       Pcap file from the specific protocol defined in the previous arg.

        Examples:
            import_pcap zigbee file1.pcap zigbee file2.pcap os4i file3.pcap --thread 2 -o zigbee-os4i.csv
            import_pcap btle file1.pcap os4i file3.pcap -t 2 -o btle-os4i.csv
            import_pcap os4i file.pcap --thread 3 --debug --output os4i.csv
IoTMap database > 
```

Here, importPCAPS is used with multiple `.pcap` files from three different protocols. 
A file named `nodes.txt` is provided to define each node used in each PCAP:
```
IoTMap database > importPcaps btle tests/capture-rpi-tempDispl-test3-merged.pcap btle tests/capture-rpi-rpi-test3.pcap btle tests/capture-rpi-tempSens-test3.pcap zigbee tests/zigbee-test3.pcapng os4i tests/coap-test3.pcapng -o tests/first-run.csv -n tests/nodes.txt -t 2 
```
It takes some time to convert and populate the database, so it may be a good time for a coffee =)

When the database is populated, it is ready for queries. 
For example, we can list the nodes:

```
IoTMap database > getNodes
 id  dl addresses                                                              nwk addresses
----------------------------------------------------------------------------------------------------------------------------------------------------------------
 0   ['0x0']                                                                   ['0x0']
 1   ['0x7b65']                                                                ['0x7b65']
 2   ['0x3181']                                                                ['0x3181']
 3   ['b8:27:eb:8c:b2:4f', '0xbeef']                                           ['b8:27:eb:8c:b2:4f', '0xbeef']
 4   ['00:12:4b:00:12:04:cb:03', '00:12:4b:00:12:04:cb']                       ['fe80::212:4b00:1204:cb03', 'fe80::212:4b:00:12:04:cb']
 5   ['dc:d0:17:9d:1d:5d']                                                     ['dc:d0:17:9d:1d:5d']
 6   ['b8:27:eb:36:1b:9d', '00:12:4b:00:0e:0d:82', '00:12:4b:00:0e:0d:82:57']  ['b8:27:eb:36:1b:9d', 'bbbb::ba27:ebff:fe9c:b137', '::212:4b00:e0d:8257']
 7   ['e0:14:9e:14:11:72']                                                     ['e0:14:9e:14:11:72']
 8   ['00:12:4b:00:16:65:27:07', '00:12:4b:00:16:65:27']                       ['::212:4b00:1665:2707', 'fe80::212:4b:00:16:65:27']
 9   ['00:12:4b:00:12:77:98:06', '00:12:4b:00:12:77:98']                       ['::212:4b00:1277:9806', 'fe80::212:4b:00:12:77:98']
 10  ['00:12:4b:00:12:04:c9:2d', '00:12:4b:00:12:04:c9']                       ['::212:4b00:1204:c92d', 'fd00::212:4b00:1204:c92d']
 11  ['00:12:4b:00:12:04:ce:a4', '00:12:4b:00:12:04:ce']                       ['::212:4b00:1204:cea4', 'fe80::212:4b:00:12:04:ce', 'fd00::212:4b00:1204:cea4']
IoTMap database > 
```

Verify the import completed successfully with the neo4j webapp: http://localhost:7474.

![neo4j imports](images/import-pcaps.PNG)

Two relationships have been created and prove that the import was successful. 
When importing data from pcaps, IoTmap will only create the data link graph. 
To model the other graphs, use the modelling module.

### Graphs modelling

Now, model graphs based on the data previously imported.
The remainder of this walkthrough will focus on the **modelling** module. 

```
IoTMap database > modelling
IoTMap modelling > help

Core commands
=============

 Commands   Description
--------------------------------
 database   Use database mode.
 sniffing   Use sniffing mode.
 exploit    Use exploit mode.
 modelling  Use modelling mode.


Modelling commands
==================

        Map the network of IoT devices detected by sniffing.

List of available commands :
        appGraph
        compareTo
        dlGraph
        help
        nwkGraph
        option
        run
        set
        transGraph

For more information about any commands hit :
        <command name> -h

IoTMap modelling > option

Module Options (modelling):

 Name     Current Settings  Required  Description
-------------------------------------------------------------------------------------------------------------------------------------
 level    4                 False     Set the number of layers of the graph [default: 4].
 csvFile  None              False     CSV file containing packets converted into unified format.
 tdelta1  0.6               False     Delay for an object to respond to a request. This value is used to build the transport graph.
 tdelta2  0.7               False     Delay for an object to forward a packet. This value is used to build the transport graph.
 adelta   1.5               False     Delay for a controller to forward a packet. This value is used to build the application graph.

IoTMap modelling >  
```

This module comes with different options that can be set with the command **set**. 
The command `option` shows the default values used to create graphs.

Regarding what you want to model, you can generate a graph step by step using the appropriate function. 
If you want to model only the network graph, then use the nwkGraph function and so on. 
This example will model all the graphs to the application graph. 

Let's start with the network graph:
```
IoTMap modelling > nwkGraph -h
Generate the network graph of the modelling. If uppers layers have already been generated, this function
        deletes all upper layers.

        Usage: nwkGraph [-h] [--filename filename]

        Options:
            -h, --help               Print this help menu
            -f, --filename filename  File with packets at unified format to generate the graph.
IoTMap modelling >        
```

Then continue with the other graphs:
```
IoTMap modelling > nwkGraph
IoTMap modelling > transGraph
IoTMap modelling > appGraph
IoTMap modelling >
```

If you already have communications formatted with the unified format, you can use it in the **modelling** module and automate the graphs modelling. 
With this options, you can skip the intermediate graph generation and go straight to the final graph you want to model :

```
IoTMap modelling > appGraph -f tests/test-all-with-protocol.csv
```

To observe the modelling newly created, visit http://localhost:7474 

Relationships have been added on the left side panel, the application graph matches the INTERACT label.

![neo4j imports](images/application-graph.PNG)

If you want to regenerate the application graph with different delta values, 
simply rerun the command with the delta option:
```
IoTMap modelling > appGraph -d 100
IoTMap modelling >
```
The old transmissions are replaces with the new ones. 
If you want to modify the delta values for the transport graph, set their value with the **set** command:
```
IoTMap modelling > appGraph -d 100                                              
IoTMap modelling > set tdelta1 100                                              
tdelta1 set to 100
IoTMap modelling > set tdelta2 100                                              
tdelta2 set to 100
IoTMap modelling > appGraph -d 100                                              
IoTMap modelling >  
```

The graph is now updated with the new value:
![neo4j imports](images/application-graph-100.PNG)
