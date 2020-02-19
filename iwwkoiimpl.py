from scapy.all import *

# from progress.bar import Bar
# from colorama import Fore, Back, Style

from iwwkoiimpl_modules import module_handler
from iwwkoiimpl_modules import output
from iwwkoiimpl_modules import argument_handler
from iwwkoiimpl_modules import default_parameters
import re


from scapy.layers.http import HTTPRequest



if __name__ == "__main__":

    try:
        # ---------- parse arguments ----------
        # todo delete
        pcapname, output_type, characters_around_leak = "pcap.pcap", 'json', None
        # pcapname, output_type, characters_around_leak = argument_handler.parse_arguments()

        if characters_around_leak is None:
            characters_around_leak = default_parameters.Values.characters_around_leak
        if output_type is None:
            output_type = default_parameters.Values.output

        # ---------- read the input ----------
        loaded_pcap = rdpcap(pcapname)
        # ---------- transform to a readable format ----------
        sessions = loaded_pcap.sessions()

        # apply all the nice modules and detect the leaking data
        leaks = []

        module_handler.process_sessions(sessions, leaks)

        # ---------- OUTPUT ----------
        output.out(leaks, output_type)
    except Exception as e:
        print(e)
        raise

