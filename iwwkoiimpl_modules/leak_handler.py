from iwwkoiimpl_modules import regex
from iwwkoiimpl_modules import ner
from iwwkoiimpl_modules import leak

class LeakHandler:
    leaks = []

def process_packet(packet):
    """
    Extracts leaks from a packet, creates a class Leak and stores it in LeakHandler.leaks
    :param packet: scapy.packet
    :return:
    """
    try:
        # ---------- TCP ----------
        if packet.haslayer('TCP'):
            # ---------- ---------- HTTP ----------
            if packet.haslayer('HTTP') and packet['IP'].dport == 80:
                request = None
                user_agent = None
                # extracting HTTP specific fields and context of potential leak
                if packet.haslayer('HTTPRequest'):
                    request = packet['HTTPRequest'].Method.decode() + " " + packet['HTTPRequest'].Host.decode() + packet['HTTPRequest'].Path.decode()
                    user_agent = packet['HTTPRequest'].User_Agent.decode()
                    context = leak.Context.HTTPRequest
                    # todo see if to do this or not
                    # leak.LeakData.leaked_user_agents.add(user_agent)
                    # leak.LeakData.leaked_requests.add(request)
                    # todo find all specific things for this one


                elif packet.haslayer('HTTPResponse'):
                    context = leak.Context.HTTPResponse
                else:
                    context = leak.Context.HTTP

                # todo ner_detector
                # def process_sessions(sessions, leaks):
                #     # initialize
                #     ner_detector = ner.NERLeakDetector()
                #     dns_string = ''
                #
                #     for session in sessions:
                #         for packet in sessions[session]:
                # ner_detector.get_leaks_from_session(packet, 'TCP')
                data_found, regexed_leaks = regex.get_leaks(packet)
                if data_found:
                    LeakHandler.leaks.append(leak.HTTPLeak(packet['IP'].src, packet['IP'].dst, packet['IP'].dport, request, user_agent, context, regexed_leaks))


        # ---------- UDP ----------
        #todo add for DNS too
        # elif packet.haslayer('UDP'):
        #     # ---------- ---------- DNS ----------
        #     if packet.haslayer('DNS') and packet['IP'].dport == 53:
        #         if len(dns_string) > 500000:
        #             ner_detector.get_leaks_from_session(dns_string, 'UDP')
        #             data_found, regexed_info = regex.get_DNS_leaks_from_session(dns_string)
        #             if data_found:
        #                 leaks.append(regexed_info)
        #             dns_string = ''
        #
        #         dns_string = dns_string + "\n" + str(packet['UDP'].payload)

    except IndexError:
        pass




