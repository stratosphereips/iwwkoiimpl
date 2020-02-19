import re

from iwwkoiimpl_modules import leak
from iwwkoiimpl_modules import default_parameters


class Expressions:
    templates = {
        'package_name': ['[a-z]+\.[a-z]+\.[a-z]+[a-z\.]*'],
        'carrier_info' : ['carrier', 'netoper'],
        'versions': ['version', 'uiver', 'ver'],
        'os_info': ['osver', 'android', 'ios', 'bundle', 'sdkver', 'sdk', 'sdktype'],
        'basic_info': ['nokia', 'iphone', 'api', 'chrome'],
        'hardware_specifications': ['cpu', 'imei', 'manufacturer', 'model', 'scn', 'scrn', 'orientation', 'screen.size', 'density'],
        'info_fields': ['[a-z]+=[0-9A-Za-z]+'],
        'private_information': ['twitter', 'mail', 'wifi', 'access'],
        'ids_and_access_tokens': ['user', 'id' + '.' * 10, 'gid', 'cookie', 'spid', 'cid', 'muid', 'pid', 'muid', 'aid' ],
        'language': ['en', 'us', 'cs', 'cz', 'lang', 'es', 'lang'],
        'password': ['password', 'pwd'],
        'location': ['loc', 'lat', 'lon', 'geo', 'timezone'],
        'application_information': ['time', 'format', 'ver', 'version', 'state', 'tracking', 'position', 'appname'],
        'file_image': [],
        'file_video': [],
        'other_data': ['data', '[a-z]+=[a-z]+']
    }


def get_HTTP_leaks_from_session(packet) -> [bool, leak.HTTPLeak]:
    characters_around_leak = default_parameters.Values.characters_around_leak

    user_agent = None
    request = None
    data_found = False

    context = 0

    regexed_leaks = []  # list of strings
    # todo problem with disected request
    if packet.haslayer('HTTPRequest'):
        # method + URL
        request = packet['HTTPRequest'].Method.decode() + " " + packet['HTTPRequest'].Host.decode() + packet[
            'HTTPRequest'].Path.decode()
        user_agent = packet['HTTPRequest'].User_Agent.decode()
        context = leak.Context.HTTPrequest

    elif packet.haslayer('HTTPResponse'):
        context = leak.Context.HTTPresponse
        pass

    packet_string = str(packet['TCP'].payload)

    for category, expressions in Expressions.templates.items():
        for e in expressions:
            x = re.findall('.' * characters_around_leak + e + '.' * characters_around_leak, packet_string, re.IGNORECASE)
            if len(x) > 0:
                regexed_leaks.append(leak.LeakData(x, context, category))
                data_found = True
    if data_found:
        return True, leak.HTTPLeak(packet['IP'].src, packet['IP'].dst, packet['IP'].dport, request,
                                   user_agent, regexed_leaks)
    else:
        return False, None
