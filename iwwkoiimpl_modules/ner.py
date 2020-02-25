import spacy
import urllib.parse
import re

from iwwkoiimpl_modules import leak

# Entities:  #CARDINAL DATE EVENT FAC GPE LANGUAGE LAW LOC MONEY NORP ORDINAL ORG PERCENT PERSON PRODUCT QUANTITY TIME WORK_OF_ART



class NERLeakDetector:
    nlp = spacy.load("en_core_web_sm")

    def get_leaks_from_session(self, packet, protocol) -> [bool, leak.HTTPLeak]:
        if protocol == 'TCP':
            packet_string = str(packet[protocol].payload)
        elif protocol == 'UDP':
            packet_string = packet

        mystring = urllib.parse.unquote_plus(packet_string)
        x = re.sub("[^a-zA-Z0-9,\.]", " ", mystring)
        doc = self.nlp(x)


        for ent in doc.ents:
            if ent.label_ in leak.LeakData.leaked_based_on_ner:
                leak.LeakData.leaked_based_on_ner[ent.label_] = leak.LeakData.leaked_based_on_ner[ent.label_] + [ent.text]
            else:
                leak.LeakData.leaked_based_on_ner[ent.label_] = [ent.text]



# day1
# fast regex for a string from the packet blub
# dont care about context
# dont delete HTTP code
# any protocol - use as a blob, use regex




