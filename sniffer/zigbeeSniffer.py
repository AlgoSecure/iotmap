"""zigbeeSniffer

This program is an interface to use the killerbee firmware to sniff ZigBee communications

Usage:
    zigbeeSniffer.py [-v] [-d <device>] [-c <channel>] [-o <file>] [-n <nbpkts>]

Options:
    -h, --help             Print this help message.
    -v, --verbose          Use a debug mode.
    -d, --device device    Set the device to use to sniff communications. [Default: None]
    -n, --nbpkts nbpkts    Define the number of packet to sniff before stopping the interception. [Default: 10000]
    -c, --channel channel  Set the channel on which the sniffer listens. [Default: 15]
    -o, --output file      Filename of the pcap storing the sniffed traffic. [Default: zigbee.pcap]

"""

from docopt import docopt, DocoptExit
import logging
import io
from contextlib import redirect_stdout

from killerbee import KillerBee, PcapDumper, DLT_IEEE802_15_4
from .sniffers import Sniffer

class zigbeeSniffer(Sniffer):
    def __init__(self, options):
        name, self.device, self.nbpkts, self.channel = options

        if name is None:
            name = 'zigbee'

        if len(self.device) != 1:
            print(f'[i] This sniffer can handle only one device at the same time. This sniffer will use the device {self.device[0]}')
        self.device = self.device[0]

        Sniffer.__init__(self, name)
        self.outputFile = '/home/jnt/zigbee.pcap'
        self.redirect = io.StringIO()
        #device, self.nbpkts, self.channel = options
        # device, self.nbpkts, self.channel,  self.outputFile= options
        self.kb = KillerBee(self.device)
        try:
            self.kb.set_channel(self.channel, 0)
        except ValueError as e:
            print('ERROR:' + e)
            exit(1)
        
    def run(self):
        self.kb.sniffer_on()
        # Create a PCAP dumper to write packets to a pcap
        with PcapDumper(DLT_IEEE802_15_4, self.outputFile, ppi=False) as pd:
            
            #rf_freq_mhz = (args.channel - 10) * 5 + 2400
            #print("zbwireshark: listening on \'{0}\'".format(kb.get_dev_info()[0]))
            rf_freq_mhz = self.kb.frequency(self.channel, 0) / 1000.0
            print("zbwireshark: listening on \'{0}\', channel {1}, page {2} ({3} MHz), link-type DLT_IEEE802_15_4, capture size 127 bytes".format(self.kb.get_dev_info()[0], self.channel, 0, rf_freq_mhz))
            try:
                packetcount = 0
                while self.nbpkts != packetcount:
                    with redirect_stdout(self.redirect):
                        if self.terminated():
                            print(f"{self.name} is quitting")
                            break

                        # Wait for the next packet
                        packet = self.kb.pnext()
                        
                        if packet != None:
                            packetcount+=1
                            pd.pcap_dump(packet['bytes'], ant_dbm=packet['dbm'], freq_mhz=rf_freq_mhz)
                        
            except IOError as e:
                if e.errno == 32:
                    #print("ERROR: Pipe broken. Was Wireshark closed or stopped?")
                    pass
                else:
                    raise
                
            self.kb.sniffer_off()
            print("{0} packets captured".format(packetcount))


# if __name__ == '__main__':
#     try:
#         args = docopt(__doc__)
#     except DocoptExit:
#         print(__doc__)
#     else:
#         device = args['--device'] if args['--device'] != 'None' else None
#         options = [args['--output'], int(args['--nbpkts']), int(args['--channel']), device]

#         zbs = zigbeeSniffer(options)
#         zbs.run()
        
        
