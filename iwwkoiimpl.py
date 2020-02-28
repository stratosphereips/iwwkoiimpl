from scapy.all import *

from iwwkoiimpl_modules import leak_handler
from iwwkoiimpl_modules import argument_handler
from iwwkoiimpl_modules.parameters import Values


def packet_process(packet):
    leak_handler.find_leaks(packet)


if __name__ == "__main__":

    try:
        # ---------- parse arguments ----------
        argument_handler.parse_arguments()

        output_filename = 'leaks_from_' + Values.pcap_name.rsplit('.',1)[0].rsplit('/',1)[-1]

        # ---------- process the input ----------
        print("processing pcap... " + Values.pcap_name)

        load_layer('http')
        sniff(filter=Values.filter, offline=Values.pcap_name, prn=packet_process, session=TCPSession)
        print("processing done... ")

        # ---------- save leaks to a file ----------
        print("saving to file: ", output_filename)
        leak_handler.out(Values.output_type, output_filename)


    except Exception as e:
        # todo handle better
        print(e)
        raise
