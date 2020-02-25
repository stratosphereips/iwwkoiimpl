from scapy.all import *

# from progress.bar import Bar
# from colorama import Fore, Back, Style

from iwwkoiimpl_modules import leak_handler
from iwwkoiimpl_modules import output
from iwwkoiimpl_modules import argument_handler
from iwwkoiimpl_modules import default_parameters
import re
import os

from scapy.layers.http import HTTPRequest

import spacy
import urllib.parse
import re


def packet_processing(packet):
    leak_handler.process_packet(packet)


if __name__ == "__main__":
    try:
        # ---------- parse arguments ----------
        # todo delete
        pcapname, output_type, characters_around_leak = 'pcaps/20191025173326-billowy_polite_10.8.0.177_10290000.pcap', 'json', None
        # pcapname, output_type, characters_around_leak = argument_handler.parse_arguments()

        # todo arguments
        if characters_around_leak is None:
            characters_around_leak = default_parameters.Values.characters_around_leak
        if output_type is None:
            output_type = default_parameters.Values.output
        output_filename = 'leaks_from_' + pcapname.rsplit('.',1)[0].rsplit('/',1)[-1] + '.json'


        # ---------- process the input ----------
        print("processing pcap... " + pcapname)
        # todo figure out the filter
        sniff(filter='tcp dst port 80 or udp dst port 53', offline=pcapname, prn=packet_processing)
        print("processing done... ")
        print("saving to file: ", output_filename)
        output.json_out(output_filename)


    except Exception as e:
        print(e)
        raise
