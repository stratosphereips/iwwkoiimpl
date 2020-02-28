import spacy
import urllib.parse
import re

from iwwkoiimpl_modules import leak

# Entities:  #CARDINAL DATE EVENT FAC GPE LANGUAGE LAW LOC MONEY NORP ORDINAL ORG PERCENT PERSON PRODUCT QUANTITY TIME WORK_OF_ART

class NERLeakDetector:
    """
    Loads a ner model and classifies named entities.
    """
    nlp = spacy.load("en_core_web_sm")

    def get_leaks(self, packet_string: str, leaks_based_on_ner: dict) -> [bool, list]:
        """
        Classifies input string and saves leaked data to their corresponding entities to a dictionary that is passed as argument.
        :param packet_string: str
        :param leaks_based_on_ner: dict dictionary that stores leaked strings
        :return: None
        """
        mystring = urllib.parse.unquote_plus(packet_string)
        x = re.sub("[^a-zA-Z0-9,\.]", " ", mystring)
        doc = self.nlp(x)


        for ent in doc.ents:
            if ent.label_ in leaks_based_on_ner:
                leaks_based_on_ner[ent.label_] = leaks_based_on_ner[ent.label_] + [ent.text]
            else:
                leaks_based_on_ner[ent.label_] = [ent.text]

