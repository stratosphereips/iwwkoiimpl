from scapy.all import *

import spacy
import json
from spacy.matcher import Matcher
from spacy.lang.en import English
# --------------------------------------------------------------------

import zlib


def process_packet(packet):
    if packet.haslayer('TCP'):
        if (len(packet['TCP'].payload) > 0):
            print(str(zlib.decompress(bytes(packet['HTTP'].payload))))

if __name__ == "__main__":

    load_layer("http")
    packets = rdpcap('pcaps/tcp80_spark.pcap')

    sniff(offline="pcaps/decode.pcap", prn=process_packet, session=TCPSession)  # pcap
    quit()
    # nlp = spacy.blank("en").from_disk("./model")
    #
    # test_text = 'asdf iPhone adfa'
    #
    # doc = nlp(test_text)
    #
    # for ent in doc.ents:
    #     print(ent)
    # quit()

    load_layer("http")
    packets = rdpcap('pcaps/tcp80_spark.pcap')

    # sniff(offline="pcaps/tcp80_spark.pcap", prn=process_packet, session=TCPSession)  # pcap
    http_string = ''
    for packet in packets:
        if packet.haslayer('TCP'):
            if (len(packet['TCP'].payload) > 0):
                http_string = http_string + str(packet['TCP'].payload)
    # print(http_string.split('\r\n'))

    TEXTS = []
    for i in http_string.split('\\r\\n'):
        x = re.sub("[^a-zA-Z0-9,\.]", " ", i).strip()
        if len(x) > 0:
            TEXTS.append(x)

    # print(TEXTS)
    # quit()

    TEXTS = ['How to preorder the iPhone X', 'iPhone X is coming', 'Should I pay $1,000 for the iPhone X?', 'The iPhone 8 reviews are here', 'Your iPhone goes up to 11 today', 'I need a new phone! Any tips?']
    TEXTS = ['Accept Encoding  gzip, deflate', 'User Agent  server bag  iPhone OS,11.4.1,15G77,iPhone7,1', 'User Agent  trustd  unknown version  CFNetwork 902.2 Darwin 17.7.0',  'User Agent  iPhone7,1 11.4.1  15G77', 'Host  init.ess.apple.com', 'Connection  keep alive', 'User Agent  server bag  iPhone OS,11.4.1,15G77,iPhone7,1', 'Accept Encoding  gzip, deflate', 'User Agent  server bag  iPhone OS,11.4.1,15G77,iPhone7,1']

    nlp = English()
    matcher = Matcher(nlp.vocab)
    pattern1 = [{"LOWER": "iphone"}]
    # pattern2 = [{"LOWER": "iphone"}, {"IS_DIGIT": True, "OP": "?"}]
    matcher.add("GADGET", None, pattern1)

    TRAINING_DATA = []

    # Create a Doc object for each text in TEXTS
    for doc in nlp.pipe(TEXTS):
        # Match on the doc and create a list of matched spans
        spans = [doc[start:end] for match_id, start, end in matcher(doc)]
        # Get (start character, end character, label) tuples of matches
        entities = [(span.start_char, span.end_char, "GADGET") for span in spans]
        # Format the matches as a (doc.text, entities) tuple
        training_example = (doc.text, {"entities": entities})
        # Append the example to the training data
        TRAINING_DATA.append(training_example)

    print(*TRAINING_DATA, sep="\n")
    # quit()
    # TRAINING_DATA=[['How to preorder the iPhone X', {'entities': [[20, 28, 'GADGET']]}], ['iPhone X is coming', {'entities': [[0, 8, 'GADGET']]}], ['Should I pay $1,000 for the iPhone X?', {'entities': [[28, 36, 'GADGET']]}], ['The iPhone 8 reviews are here', {'entities': [[4, 12, 'GADGET']]}], ['Your iPhone goes up to 11 today', {'entities': [[5, 11, 'GADGET']]}], ['I need a new phone! Any tips?', {'entities': []}]]

    nlp = spacy.blank("en")
    ner = nlp.create_pipe("ner")
    nlp.add_pipe(ner)
    ner.add_label("GADGET")

    # Start the training
    nlp.begin_training()

    # Loop for 10 iterations
    for itn in range(10):
        print(itn)
        # Shuffle the training data
        random.shuffle(TRAINING_DATA)
        losses = {}

        # Batch the examples and iterate over them
        for batch in spacy.util.minibatch(TRAINING_DATA, size=2):
            texts = [text for text, entities in batch]
            annotations = [entities for text, entities in batch]
            # Update the model
            nlp.update(texts, annotations, losses=losses)
            print(losses)

    nlp.to_disk("./model")

    test_text = 'User Agent  server bag  iphonek OS,11.4.1,15G77,iPhone,1'

    doc = nlp(test_text)

    for ent in doc.ents:
        print(ent.text, ent.label_)
    quit()


    # --------------------------------------------------------------------

    # TODO RECYCLED CODE

    # TODO more regex

    # 'C': {
    #     'info_fields': ['[a-z]+=[0-9A-Za-z]+', '[\'"].{0,1}:.{0,1}[\'"]'],
    #     'application_information': ['time', 'format', 'ver', 'version', 'state', 'tracking', 'position',
    #                                 'appname'],
    #     'other_data': ['data', '[a-z]+=[a-z]+'],
    #
    #     'country_codes': ["BD", "BGD", "BE", "BEL", "BF", "BFA", "BG", "BGR", "BA", "BIH", "BB", "BRB", "WF",
    #                       "WLF",
    #                       "BL", "BLM",
    #                       "BM", "BMU", "BN", "BRN", "BO", "BOL", "BH", "BHR", "BI", "BDI", "BJ", "BEN", "BT",
    #                       "BTN",
    #                       "JM", "JAM",
    #                       "BV", "BVT", "BW", "BWA", "WS", "WSM", "BQ", "BES", "BR", "BRA", "BS", "BHS", "JE",
    #                       "JEY",
    #                       "BY", "BLR",
    #                       "BZ", "BLZ", "RU", "RUS", "RW", "RWA", "RS", "SRB", "TL", "TLS", "RE", "REU", "TM",
    #                       "TKM",
    #                       "TJ", "TJK",
    #                       "RO", "ROU", "TK", "TKL", "GW", "GNB", "GU", "GUM", "GT", "GTM", "GS", "SGS", "GR",
    #                       "GRC",
    #                       "GQ", "GNQ",
    #                       "GP", "GLP", "JP", "JPN", "GY", "GUY", "GG", "GGY", "GF", "GUF", "GE", "GEO", "GD",
    #                       "GRD",
    #                       "GB", "GBR",
    #                       "GA", "GAB", "SV", "SLV", "GN", "GIN", "GM", "GMB", "GL", "GRL", "GI", "GIB", "GH",
    #                       "GHA",
    #                       "OM", "OMN",
    #                       "TN", "TUN", "JO", "JOR", "HR", "HRV", "HT", "HTI", "HU", "HUN", "HK", "HKG", "HN",
    #                       "HND",
    #                       "HM", "HMD",
    #                       "VE", "VEN", "PR", "PRI", "PS", "PSE", "PW", "PLW", "PT", "PRT", "SJ", "SJM", "PY",
    #                       "PRY",
    #                       "IQ", "IRQ",
    #                       "PA", "PAN", "PF", "PYF", "PG", "PNG", "PE", "PER", "PK", "PAK", "PH", "PHL", "PN",
    #                       "PCN",
    #                       "PL", "POL",
    #                       "PM", "SPM", "ZM", "ZMB", "EH", "ESH", "EE", "EST", "EG", "EGY", "ZA", "ZAF", "EC",
    #                       "ECU",
    #                       "IT", "ITA",
    #                       "VN", "VNM", "SB", "SLB", "ET", "ETH", "SO", "SOM", "ZW", "ZWE", "SA", "SAU", "ES",
    #                       "ESP",
    #                       "ER", "ERI",
    #                       "ME", "MNE", "MD", "MDA", "MG", "MDG", "MF", "MAF", "MA", "MAR", "MC", "MCO", "UZ",
    #                       "UZB",
    #                       "MM", "MMR",
    #                       "ML", "MLI", "MO", "MAC", "MN", "MNG", "MH", "MHL", "MK", "MKD", "MU", "MUS", "MT",
    #                       "MLT",
    #                       "MW", "MWI",
    #                       "MV", "MDV", "MQ", "MTQ", "MP", "MNP", "MS", "MSR", "MR", "MRT", "IM", "IMN", "UG",
    #                       "UGA",
    #                       "TZ", "TZA",
    #                       "MY", "MYS", "MX", "MEX", "IL", "ISR", "FR", "FRA", "IO", "IOT", "SH", "SHN", "FI",
    #                       "FIN",
    #                       "FJ", "FJI",
    #                       "FK", "FLK", "FM", "FSM", "FO", "FRO", "NI", "NIC", "NL", "NLD", "NO", "NOR", "NA",
    #                       "NAM",
    #                       "VU", "VUT",
    #                       "NC", "NCL", "NE", "NER", "NF", "NFK", "NG", "NGA", "NZ", "NZL", "NP", "NPL", "NR",
    #                       "NRU",
    #                       "NU", "NIU",
    #                       "CK", "COK", "XK", "XKX", "CI", "CIV", "CH", "CHE", "CO", "COL", "CN", "CHN", "CM",
    #                       "CMR",
    #                       "CL", "CHL",
    #                       "CC", "CCK", "CA", "CAN", "CG", "COG", "CF", "CAF", "CD", "COD", "CZ", "CZE", "CY",
    #                       "CYP",
    #                       "CX", "CXR",
    #                       "CR", "CRI", "CW", "CUW", "CV", "CPV", "CU", "CUB", "SZ", "SWZ", "SY", "SYR", "SX",
    #                       "SXM",
    #                       "KG", "KGZ",
    #                       "KE", "KEN", "SS", "SSD", "SR", "SUR", "KI", "KIR", "KH", "KHM", "KN", "KNA", "KM",
    #                       "COM",
    #                       "ST", "STP",
    #                       "SK", "SVK", "KR", "KOR", "SI", "SVN", "KP", "PRK", "KW", "KWT", "SN", "SEN", "SM",
    #                       "SMR",
    #                       "SL", "SLE",
    #                       "SC", "SYC", "KZ", "KAZ", "KY", "CYM", "SG", "SGP", "SE", "SWE", "SD", "SDN", "DO",
    #                       "DOM",
    #                       "DM", "DMA",
    #                       "DJ", "DJI", "DK", "DNK", "VG", "VGB", "DE", "DEU", "YE", "YEM", "DZ", "DZA", "US",
    #                       "USA",
    #                       "UY", "URY",
    #                       "YT", "MYT", "UM", "UMI", "LB", "LBN", "LC", "LCA", "LA", "LAO", "TV", "TUV", "TW",
    #                       "TWN",
    #                       "TT", "TTO",
    #                       "TR", "TUR", "LK", "LKA", "LI", "LIE", "LV", "LVA", "TO", "TON", "LT", "LTU", "LU",
    #                       "LUX",
    #                       "LR", "LBR",
    #                       "LS", "LSO", "TH", "THA", "TF", "ATF", "TG", "TGO", "TD", "TCD", "TC", "TCA", "LY",
    #                       "LBY",
    #                       "VA", "VAT",
    #                       "VC", "VCT", "AE", "ARE", "AD", "AND", "AG", "ATG", "AF", "AFG", "AI", "AIA", "VI",
    #                       "VIR",
    #                       "IS", "ISL",
    #                       "IR", "IRN", "AM", "ARM", "AL", "ALB", "AO", "AGO", "AQ", "ATA", "AS", "ASM", "AR",
    #                       "ARG",
    #                       "AU", "AUS",
    #                       "AT", "AUT", "AW", "ABW", "IN", "IND", "AX", "ALA", "AZ", "AZE", "IE", "IRL", "ID",
    #                       "IDN",
    #                       "UA", "UKR",
    #                       "QA", "QAT", "MZ", "MOZ"]
    #
    # }

