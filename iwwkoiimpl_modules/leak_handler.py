from iwwkoiimpl_modules import regex
from iwwkoiimpl_modules import leak
from iwwkoiimpl_modules import output
from iwwkoiimpl_modules.leak_store import LeakStore


def out(output_type : str, output_file_name=None):
    """
    Calls output methods.
    :param output_type: str
    :param output_file_name: str
    :return: None
    """
    if output_type == 'json':
        output.json_out(output_file_name, LeakStore.leaks)
    elif output_type == 'std':
        output.std_out(LeakStore.leaks)

def find_leaks(packet):
    """
    Handles input of packets and passes them to detection modules.
    Handles output from detection modules, creates a class Leak and stores it in LeakHandler.
    :param packet: scapy.packet
    :return: None
    """
    try:
        # ---------- TCP ----------
        if packet.haslayer('TCP'):
            # ---------- ---------- HTTP ----------
            if packet.haslayer('HTTP') and packet['IP'].dport == 80:
                user_agent_regexed_leaks = []
                request = None
                user_agent = None
                # extracting HTTP specific fields and context of potential leak
                if packet.haslayer('HTTPRequest'):
                    try:
                        context = leak.Context.HTTPRequest

                        request = packet['HTTPRequest'].Method.decode() + " " + packet['HTTPRequest'].Host.decode() + packet['HTTPRequest'].Path.decode()
                        LeakStore.leaked_requests.add(request)

                        user_agent = packet['HTTPRequest'].User_Agent.decode()
                        LeakStore.leaked_user_agents.add(user_agent)

                        # specific regualr expressions
                        # - package name in User-Agent
                        data_found, user_agent_regexed_leaks = regex.get_specific_leaks(user_agent, 'package_name_in_user_agent')
                    except AttributeError as a:
                        pass

                elif packet.haslayer('HTTPResponse'):
                    context = leak.Context.HTTPResponse
                else:
                    context = leak.Context.HTTP

                specific_regexed_leaks = user_agent_regexed_leaks # + other specific regexed leaks

                packet_string = str(packet['TCP'].payload)
                LeakStore.ner_detector.get_leaks(packet_string, LeakStore.leaks_based_on_ner)
                # data_found, packet_ner_leaks = LeakHandler.ner_detector.get_leaks(packet_string, LeakHandler.leaks_based_on_ner)
                data_found, packet_regexed_leaks = regex.get_leaks(packet_string)
                regexed_leaks = specific_regexed_leaks + packet_regexed_leaks # + packet_ner_leaks
                if data_found:
                    LeakStore.leaks.append(leak.HTTPLeak(packet['IP'].src, packet['IP'].dst, packet['IP'].dport, str(packet.time), request, user_agent, context, regexed_leaks))


        # ---------- UDP ----------
        elif packet.haslayer('UDP'):
            # ---------- ---------- DNS ----------
            if packet.haslayer('DNS') and packet['IP'].dport == 53:
                LeakStore.ner_detector.get_leaks(str(packet['UDP'].payload), LeakStore.leaks_based_on_ner)
                # data_found, packet_ner_leaks = LeakHandler.ner_detector.get_leaks(str(packet['UDP'].payload), LeakHandler.leaks_based_on_ner)
                data_found, packet_regexed_leaks = regex.get_leaks(str(packet['UDP'].payload))
                regexed_leaks = packet_regexed_leaks  # + packet_ner_leaks
                if data_found:
                    LeakStore.leaks.append(leak.DNSLeak(packet['IP'].src, packet['IP'].dst, packet['IP'].dport, str(packet.time), regexed_leaks))

    except IndexError:
        pass




