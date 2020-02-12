import re

from iwwkoiimpl_modules import leak


def get_leaks_from_packet(packet,context=None) -> [bool,leak.HTTPLeak]:
    #input: TCP HTTP packet

    if context is None:
        context = 10
    #-----------------------------------------------------------------------------
    # email:
    # password:
    # ip address
    # id:
    #-----------------------------------------------------------------------------

    templates = ['twitter', 'nokia', 'iphone', 'mail', 'password', 'pwd', 'user',
                 'wifi', 'chrome', 'access','en','cz','es','lang','com','loc','lat','lon','imei','mn','android','ios','build','time','format','[0-9][0-9]\.']

    packet_string=str(bytes(packet['TCP'].payload).decode('ascii'))
    regexed_strings = [] # list of strings


    for t in templates:
        x = re.findall('.'*context+t+'.'*context,packet_string,re.IGNORECASE)
        if len(x) > 0:
            regexed_strings.extend(x)

    if len(regexed_strings) > 0:
        user_agent = None
        host = None
        request = None

        split_packet = packet_string.split('\r\n')


        for http_packet_line in split_packet:
            if request is None:
                x = re.findall('POST:|GET:', http_packet_line, re.IGNORECASE)
                if len(x) > 0:
                    request = http_packet_line
                    continue
            if user_agent is None:
                x = re.findall('User-Agent:', http_packet_line, re.IGNORECASE)
                if len(x) > 0:
                    user_agent = http_packet_line
                    continue
            if host is None:
                x = re.findall('Host:', http_packet_line, re.IGNORECASE)
                if len(x) > 0:
                    host = http_packet_line
                    continue
            if request is not None and user_agent is not None and host is not None:
                break

        return True, leak.HTTPLeak(packet['IP'].src, packet['IP'].dst, packet['IP'].dport, request, user_agent, host, regexed_strings)
    else:
        return False, None
