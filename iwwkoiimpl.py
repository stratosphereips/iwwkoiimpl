from scapy.all import *

# from progress.bar import Bar
# from colorama import Fore, Back, Style

from iwwkoiimpl_modules import module_handler
from iwwkoiimpl_modules import output
from iwwkoiimpl_modules import argument_handler
from iwwkoiimpl_modules import default_parameters
import re


from scapy.layers.http import HTTPRequest

import spacy
import urllib.parse
import re

if __name__ == "__main__":
    #
    # input_string = "GET /stripe/image?cs_email=alrogague@gmail.com;nayely.lag@gmail.com&cs_sendid=311303193515&cs_offset=0&cs_stripeid=14298&cs_esp=responsys"
    # mystring = urllib.parse.unquote_plus(input_string)
    #
    # x = re.sub("[^a-zA-Z0-9,\.]", " ", mystring)
    #
    # nlp = spacy.load("en_core_web_sm")
    # doc = nlp(x)
    # for token in doc:
    #     print(token)
    # print("_________________________________________________________")
    # for ent in doc.ents:
    #     print(ent.text, ent.label_)
    #
    # quit()

    try:
        # ---------- parse arguments ----------
        # todo delete
        pcapname, output_type, characters_around_leak = "pcaps/tcp80_spark.pcap", 'json', None
        # pcapname, output_type, characters_around_leak = argument_handler.parse_arguments()

        if characters_around_leak is None:
            characters_around_leak = default_parameters.Values.characters_around_leak
        if output_type is None:
            output_type = default_parameters.Values.output

        # ---------- read the input ----------
        print("loading... " + pcapname)
        loaded_pcap = rdpcap(pcapname)
        print("loaded... " + pcapname)
        # ---------- transform to a readable format ----------
        sessions = loaded_pcap.sessions()
        print("sessions... " + pcapname)

        # apply all the nice modules and detect the leaking data
        leaks = []

        print("processing pcap... " + pcapname)

        module_handler.process_sessions(sessions, leaks)
        print("processing done... " + pcapname)
        # ---------- OUTPUT ----------
        output.out(leaks, output_type)
    except Exception as e:
        print(e)
        raise

