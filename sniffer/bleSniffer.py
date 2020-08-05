"""bleSniffer

This program is an interface to use the btlejack firmware to sniff BLE communications

Usage:
    bleSniffer.py [-v] [-d <devices>] [-o <file>] [-f <format>] [-c <crcinit>] [-m <channel_map>]
                  [-s <hop>] [-t <timeout>] (sniff <access_address> | scan)

Options:
    -h, --help                     Print this help message.
    -v, --verbose                  Use a debug mode [Default: True].
    -d, --device device            Set the device to use to sniff communications. [Default: None]
    -m, --channel_map channel_map  Set the channel map. [Default: None]
    -c, --crcinit crcinit          Set the crcinit. [Default: None]
    -s, --hop_interval hop         Set the hop interval. [Default: None]
    -t, --timeout timeout          Set the timeout. [Default: 0]
    -f, --output_format format     Set the output format of the Pcap. [Default: pcap]
    -o, --output_file file         Set the output name of the Pcap. [Default: ble.pcap]

    sniff <access_address>         Run the sniffing function for a specific communication.
    scan                           Run the scan mode to identify access_address avalaible.

"""

from docopt import docopt, DocoptExit
import logging
import signal
import datetime

from .sniffers import Sniffer
import io
from contextlib import redirect_stdout

from btlejack.pcap import PcapBleWriter, PcapNordicTapWriter,  PcapBlePHDRWriter
from btlejack.ui import (CLIAccessAddressSniffer, CLIConnectionRecovery,
                         CLIConnectionSniffer, ForcedTermination,
                         SnifferUpgradeRequired)
from btlejack.helpers import *
from btlejack.link import DeviceError
from btlejack.version import VERSION
from btlejack.session import BtlejackSession, BtlejackSessionError

class bleSniffer(Sniffer):
    # def __init__(self, output, output_format, devices=None, crc=None, chm=None,
    #              hop=None, verbose=True, timeout=0, hijack=None, jamming=None):
    def __init__(self, options):
        name, self.device, self.nbpkts, self.access_address, self.type = options
        if name is None:
            name = 'btle'

        Sniffer.__init__(self, name)
        #elf.devices, self.nbpkts, self.access_address, self.type = options
        # self.devices, self.crc, self.chm, self.hop, self.verbose, self.timeout, self.hijack, self.jamming, output, output_format = options
        #self.devices = devices
        self.crc = None
        self.chm = None
        self.hop = None
        self.verbose = False
        self.timeout = None
        self.hijack = None
        self.jamming = None
        self.supervisor = None
        # self.crc = crc
        # self.chm = chm
        # self.hop = hop
        # self.verbose = verbose
        # self.timeout = timeout
        # self.hijack = hijack
        # self.jamming = jamming

        self.redirect = io.StringIO()

        self.output = None
            
    # This function is similar to the scan-connections option of the original btlejack project
    def scan(self):
        try:
            self.supervisor = CLIAccessAddressSniffer(verbose=self.verbose, devices=self.device)
        except DeviceError as error:
            print('[!] Please connect a compatible Micro:Bit in order to use BtleJack')
            exit(-1)
            

    def setSupervisor(self):


        output = '/home/jnt/ble-lived.pcap'
        output_format = 'll_phdr'

        if output_format.lower().strip() == 'nordic':
            self.output = PcapNordicTapWriter(output)
        elif output_format.lower().strip() == 'll_phdr':
            self.output = PcapBlePHDRWriter(output)
        else:
            self.output = PcapBleWriter(output)


        if self.type == 'sniff':
            self.sniff()
        else:
            self.follow(int(self.access_address.replace(':', ''), 16))


    # This function is similar to the follow option of the original btlejack project
    def sniff(self):
        if self.chm is not None:
            chm = int(self.chm, 16)
        else:
            chm = None
        if self.crc is not None:
            crc = int(self.crc, 16)
        else:
            crc = None

        if self.hop is not None:
            hop = self.hop
        else:
            hop = None
        try:
            cached_parameters = BtlejackSession.get_instance().find_connection(self.access_address)
            if cached_parameters is not None:
                # override parameters with those stored in cache
                for param in cached_parameters:
                    if param == 'crcinit':
                        crc = cached_parameters[param]
                creation_date = datetime.datetime.fromtimestamp(
                    cached_parameters['start']
                ).strftime('%Y-%m-%d %H:%M:%S')
                print('[i] Using cached parameters (created on %s)' % creation_date)

            try:
                self.supervisor = CLIConnectionRecovery(
                    self.access_address,
                    channel_map=chm,
                    hijack=self.hijack,
                    jamming=self.jamming,
                    hop_interval=hop,
                    crc=crc,
                    output=self.output,
                    verbose=self.verbose,
                    devices=self.device,
                    timeout=self.timeout
                )
            except SnifferUpgradeRequired as su:
                print("[i] Quitting, please upgrade your sniffer firmware")

        except DeviceError as error:
            print('[!] Please connect a compatible Micro:Bit in order to use BtleJack')
            exit(-1)

    def follow(self, deviceAddress):
        if deviceAddress is not None:
            # address is okay, feed our sniffer
            try:
                self.supervisor = CLIConnectionSniffer(
                    deviceAddress,
                    output=self.output,
                    verbose=self.verbose,
                    devices=self.device
                )

            except SnifferUpgradeRequired as su:
                print("[i] Quitting, please upgrade your sniffer firmware (-i option if you are using a Micro:Bit)")
            except DeviceError as error:
                print('[!] Please connect a compatible Micro:Bit in order to use BtleJack')
                sys.exit(-1)
        else:
            print('[!] Wrong Bluetooth Address format: %s' % self.access_address)

    def run(self):
        try:     
            self.setSupervisor()
            if self.supervisor is not None:
                # print("Interepcetion in progress")
                while True:
                    with redirect_stdout(self.redirect):
                        if self.terminated():
                            if self.output is not None:

                                self.output.close()
                            raise ForcedTermination()
                            
                        self.supervisor.process_packets()
        except ForcedTermination as e:
            print('[i] Quitting')
            # print(f'{self.redirect.getvalue()}')

# if __name__ == '__main__':
#     try:
#         args = docopt(__doc__)
#     except DocoptExit:
#         print(__doc__)
#     else:
#         devices = args['--device'] if args['--device'] != 'None' else None
#         crc = args['--crcinit'] if args['--crcinit'] != 'None' else None
#         chm = args['--channel_map'] if args['--channel_map'] != 'None' else None
#         hop = int(args['--hop_interval']) if args['--hop_interval'] != 'None' else None
#         verbose = args['--verbose']
#         timeout = int(args['--timeout'])
#         output_format = args['--output_format']
#         output = args['--output_file']

#         options = [output, output_format, devices=devices, crc, chm, hop, verbose, timeout, None, None]
        
#         bleSniffer = bleSniffer(options)

        
#         if args['sniff']:
#             print("[i] Sniff mode launched")
#             bleSniffer.sniff(int(args['<access_address>'], 16))
#         else:
#             print("[i] Scan mode launched")
#             bleSniffer.scan()

#         bleSniffer.run()
    
