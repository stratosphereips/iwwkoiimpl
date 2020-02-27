import spacy
import urllib.parse
import re

from iwwkoiimpl_modules import leak

# Entities:  #CARDINAL DATE EVENT FAC GPE LANGUAGE LAW LOC MONEY NORP ORDINAL ORG PERCENT PERSON PRODUCT QUANTITY TIME WORK_OF_ART

class NERLeakDetector:
    nlp = spacy.load("en_core_web_sm")

    def get_leaks(self, packet_string: str, leaks_based_on_ner: dict) -> [bool, list]:

        mystring = urllib.parse.unquote_plus(packet_string)
        x = re.sub("[^a-zA-Z0-9,\.]", " ", mystring)
        doc = self.nlp(x)


        for ent in doc.ents:
            if ent.label_ in leaks_based_on_ner:
                leaks_based_on_ner[ent.label_] = leaks_based_on_ner[ent.label_] + [ent.text]
            else:
                leaks_based_on_ner[ent.label_] = [ent.text]

