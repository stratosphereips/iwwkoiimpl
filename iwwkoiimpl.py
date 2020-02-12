from scapy.all import *

# from progress.bar import Bar
# from colorama import Fore, Back, Style
from iwwkoiimpl_modules import module_handler
from iwwkoiimpl_modules import output
from iwwkoiimpl_modules import argument_handler
from iwwkoiimpl_modules import default_parameters

if __name__ == "__main__":

    # ---------- parse arguments ----------
    pcapname, output_type, context = argument_handler.parse_arguments()
    if context is not None:
        default_parameters.context = context
    # ---------- read the input ----------
    loaded_pcap = rdpcap(pcapname)

    # ---------- transform to a readable format ----------
    sessions = loaded_pcap.sessions()

    # apply all the nice modules and detect the leaking data

    leaks = []

    module_handler.process_sessions(sessions, leaks)

    # ---------- OUTPUT ----------
    output.out(leaks, output_type)
