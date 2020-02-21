from iwwkoiimpl_modules import regex
from iwwkoiimpl_modules import ner



def process_sessions(sessions, leaks):
    #initialize
    ner_detector = ner.NERLeakDetector()
    dns_string=''

    for session in sessions:
        for packet in sessions[session]:
            try:
                # ---------- TCP ----------
                if packet.haslayer('TCP'):
                # ---------- ---------- HTTP ----------
                    if packet.haslayer('HTTP') and packet['IP'].dport == 80 :
                        ner_detector.get_leaks_from_session(packet, 'TCP')
                        data_found, regexed_info = regex.get_HTTP_leaks_from_session(packet)
                        if data_found:
                            leaks.append(regexed_info)

                # ---------- UDP ----------
                elif packet.haslayer('UDP'):
                # ---------- ---------- DNS ----------
                    if packet.haslayer('DNS') and packet['IP'].dport == 53:
                        if len(dns_string) > 500000:
                            ner_detector.get_leaks_from_session(dns_string, 'UDP')
                            data_found, regexed_info = regex.get_DNS_leaks_from_session(dns_string)
                            if data_found:
                                leaks.append(regexed_info)
                            dns_string=''

                        dns_string = dns_string + "\n" + str(packet['UDP'].payload)

            except IndexError:
                continue


