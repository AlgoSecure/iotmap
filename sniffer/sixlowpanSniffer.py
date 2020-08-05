"""sixlowpanSniffer

This program is an interface to use the sensniff firmware to sniff 6LoWPAN communications

Usage:
    6lpanSniffer.py [-v] [-s <sniffer>] [-d <device>] [-n <nbpkts>] [-c <channel>] [-o <file>]

Options:
    -h, --help             Print this help message.
    -s, --sniffer sniffer  Type of sniffer used (sensniffer or ARZ). [Default: sensniffer]
    -v, --verbose          Use a debug mode.
    -d, --device device    Set the device to use to sniff communications. [Default: /dev/ttyACM0]
    -n, --nbpkts nbpkts    Define the number of packet to sniff before stopping the interception. [Default: 1000]
    -c, --channel channel  Set the channel on which the sniffer listens. [Default: 25]
    -o, --output file      Filename of the pcap storing the sniffed traffic. [Default: 6lpan.pcap]

Example :
    sudo python 6lpanSniffer.py --device /dev/ttyACM0 -o sensniffer.pcap -n 200 -s sensniffer
    sudo python 6lpanSniffer.py -o arz.pcap -n 200 -s ARZ
"""

## Example :
# sudo python3.7 6lpanSniffer.py --device /dev/ttyACM0 -o sensniffer.pcap -n 200 -s sensniffer
# sudo python3.7 6lpanSniffer.py -o arz.pcap -n 200 -s ARZ

from docopt import docopt, DocoptExit
import logging
import time
import sys
import io
from contextlib import redirect_stdout

from .extmodules.sensniff import SerialInputHandler, PcapDumpOutHandler, Frame
from .sniffers import Sniffer


###### Defaults
defaults_sensniff = {
    'baudrate': 460800,
    'rts_cts': False,
}

class sixlowpanSniffer(Sniffer):
    def __init__(self, options):
        name, self.device, self.nbpkts, self.channel = options

        if len(self.device) != 1:
            print(f'[i] This sniffer can handle only one device at the same time. This sniffer will use the device {self.device[0]}')
        self.device = self.device[0]

        if name is None:
            name = '6lowpan'

        Sniffer.__init__(self, name)
        self.redirect = io.StringIO()
        self.outputFile = '/home/jnt/sensniff.pcap'
        # self.device, self.channel, self.nbpkts, self.verbose, self.outputFile = options

    def run(self):
        in_handler = SerialInputHandler(port = self.device, baudrate = defaults_sensniff['baudrate'],
                                            rts_cts = defaults_sensniff['rts_cts'])

        out_handlers = []
        out_handlers.append(PcapDumpOutHandler(self.outputFile))

        in_handler.get_channel()

        while True:
            with redirect_stdout(self.redirect):
                if self.terminated():
                    print(f"{self.name} is quitting")
                    break

                raw = in_handler.read_frame()
                if len(raw) > 0:
                    t = time.time()
                    frame = Frame(bytearray(raw), t)
                    for h in out_handlers:
                        h.handle(frame)
                        if stats['Captured'] >= self.nbpkts:
                            break


# class ARZSniffer():
#     def __init__(self, options):
#         self.channel, self.outputFile, device, self.nbpkts, self.verbose = options
        
#         self.kb = KillerBee(device)
#         try:
#             self.kb.set_channel(self.channel, 0)
#         except ValueError as e:
#             print('ERROR:' + e)
#             exit(1)
        
#     def run(self):
#         self.kb.sniffer_on()
#         # Create a PCAP dumper to write packets to a pcap
#         with PcapDumper(DLT_IEEE802_15_4, self.outputFile, ppi=False) as pd:
            
#             #rf_freq_mhz = (args.channel - 10) * 5 + 2400
#             #print("zbwireshark: listening on \'{0}\'".format(kb.get_dev_info()[0]))
#             rf_freq_mhz = self.kb.frequency(self.channel, 0) / 1000.0
#             print("zbwireshark: listening on \'{0}\', channel {1}, page {2} ({3} MHz), link-type DLT_IEEE802_15_4, capture size 127 bytes".format(self.kb.get_dev_info()[0], self.channel, 0, rf_freq_mhz))
#             try:
#                 packetcount = 0
#                 while self.nbpkts != packetcount:
#                     # Wait for the next packet
#                     packet = self.kb.pnext()
                    
#                     if packet != None:
#                         packetcount+=1
#                         pd.pcap_dump(packet['bytes'], ant_dbm=packet['dbm'], freq_mhz=rf_freq_mhz)
                        
#             except KeyboardInterrupt:
#                 pass
#             except IOError as e:
#                 if e.errno == 32:
#                     #print("ERROR: Pipe broken. Was Wireshark closed or stopped?")
#                     pass
#                 else:
#                     raise
                
#             self.kb.sniffer_off()
#             print("{0} packets captured".format(packetcount))


# if __name__ == '__main__':
#     try:
#         args = docopt(__doc__)
#     except DocoptExit:
#         print(__doc__)
#     else:
#         sniffer = args['--sniffer']
#         channel = int(args['--channel'])
#         device = args['--device'] if args['--device'] != 'None' else None
#         verbose = args['--verbose']
#         output = args['--output']
#         nbpkts = int(args['--nbpkts'])

#         options = [channel, output, device, nbpkts, verbose]
        
#         print(f'channel {channel}, device {device}, verbose {verbose}, output {output}, nbpkts {nbpkts}, sniffer {sniffer}')

#         # if(sniffer.lower() == "arz"):
#         #     from killerbee import KillerBee, PcapDumper, DLT_IEEE802_15_4
#         #     slpSniffer = ARZSniffer(options)
#         #     slpSniffer.run()
#         # else:
#         from extmodules.sensniff import Frame, SerialInputHandler, PcapDumpOutHandler, stats
#         slpSniffer = sixlowpanSniffer(options)
#         slpSniffer.run()
