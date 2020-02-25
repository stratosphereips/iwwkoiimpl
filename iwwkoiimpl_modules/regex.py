import re

from iwwkoiimpl_modules import leak
from iwwkoiimpl_modules import parameters


class Expressions:
    importance_evaluations = {
        'A_field': 1.,
        'A_match': 1.,
        'B': 0.5,
        'C': 0.1
    }

    regex_templates = {
        # todo add after context, separate word
        'specific': {
            'package_name_in_user_agent': [ '[a-z]+\.[a-z]+\.[a-z]+[a-z\.]*' ],  # in User-Agent only # todo two or three letters
        },
        'A_field': {
            'carrier_info': ['carrier', 'netoper'],
                'credentials': ['password', 'pwd', 'e?mail', 'user', 'access', 'account', 'acc', 'key'],
            'location': ['loc', 'location', 'lat?', 'latitude', 'lon?', 'longt?', 'longitude', 'geo', 'location', 'timezone'],
            'ids_and_access_tokens': ['user', 'id', 'gid', 'cookie', 'spid', 'cid', 'muid', 'pid', 'muid', 'aid'],
            'versions': ['version', 'uiver', 'ver'],
            'os_info': ['osver', 'bundle', 'sdkver', 'sdk', 'sdktype', 'api'],
            'basic_info': ['api'],
            'hardware_specifications': ['cpu', 'imei', 'manufacturer', 'model', 'scn', 'scrn', 'orientation',
                                        'screen.size', 'density', 'wifi', 'phone'],
            # 'private_information': [''],
            'language': ['language', 'lang']
        },
        'A_match':{
            'mail' : ['[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,5}']
        },
        'B': {
            'hardware': ['iphone', 'nokia'],
            'software': ['android', 'ios', 'chrome'],
            # todo names of applications
            'application_names': ['twitter', 'facebook', 'whatsapp', 'signal', 'gmail', 'google', 'apple'],
            # todo names of manufacturers
            'manufacturer_names': ['apple', 'nokia', 'xiaomi', 'siemens'],
            # todo names of operating systems
            'operating_systems': ['ios', 'android'],
            # todo
            'other': ['wifi', 'charg.....', ]
        }  # ,
    }


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



def get_specific_leaks(packet_string, category :str) -> [bool, list]:
    regexed_leaks = []  # list of LeakData
    for e in Expressions.regex_templates['specific'][category]:
        x = re.findall(e, packet_string, re.IGNORECASE)
        if len(x) > 0:
            regexed_leaks.append(leak.LeakData(x,category , 1.))
    return len(regexed_leaks) > 0, regexed_leaks

def get_leaks(packet) -> [bool, list]:
    """
    Extracts leaks using regular expressions.
    :param packet: scapy.packet
    :return [bool, leak.Leak]
    """
    characters_around_leak = str(parameters.Values.characters_around_leak)
    regexed_leaks = []  # list of LeakData
    packet_string = str(packet['TCP'].payload)

    for priority, i in Expressions.regex_templates.items():
        for category, expressions in i.items():
            if priority == 'specific':
                continue
            for e in expressions:
                x = ''
                if priority == 'A_field':
                    x = re.findall(e + '.?[=:/].{0,' + characters_around_leak + '}', packet_string, # '[^a-z_]' +
                                   re.IGNORECASE)
                elif priority == 'A_match':
                    x = re.findall(e, packet_string,re.IGNORECASE)

                elif priority == 'B' or priority == 'C':
                    x = re.findall(
                        '.{0,' + characters_around_leak + '}[^a-z]' + e + '[^a-z]{1}.{0,' + characters_around_leak + '}',
                        packet_string, re.IGNORECASE)
                if len(x) > 0:
                    # todo check if to even do this
                    if priority in leak.LeakData.leaks_sorted_by_priority:
                        leak.LeakData.leaks_sorted_by_priority[priority] = leak.LeakData.leaks_sorted_by_priority[priority] + x
                    else:
                        leak.LeakData.leaks_sorted_by_priority[priority] = x
                    if category in leak.LeakData.leaks_sorted_by_category:
                        leak.LeakData.leaks_sorted_by_category[category] = leak.LeakData.leaks_sorted_by_category[category] + x
                    else:
                        leak.LeakData.leaks_sorted_by_category[category] = x
                    regexed_leaks.append(leak.LeakData(x, category, Expressions.importance_evaluations[priority]))

    return len(regexed_leaks) > 0, regexed_leaks


# def get_DNS_leaks_from_session(packet) -> [bool, leak.DNSLeak]:
#     characters_around_leak = str(parameters.Values.characters_around_leak)
#     data_found = False
#     regexed_leaks = []  # list of strings
#     # if packet.haslayer('DNSRequest'):
#     #     context = leak.Context.DNSRequest
#     # elif packet.haslayer('DNSResponse'):
#     #     context = leak.Context.DNSResponse
#     # else:
#     #     context = leak.Context.DNS
#
#     # packet_string = str(packet['UDP'].payload)
#     context = leak.Context.DNS
#     packet_string = packet
#
#     for priority, i in Expressions.regex_templates.items():
#         for category, expressions in i.items():
#             if priority == 'specific':
#                 continue
#             for e in expressions:
#                 x = ''
#                 if priority == 'A_field':
#                     x = re.findall(e + '.?[=:/].{0,' + characters_around_leak + '}', packet_string, # '[^a-z_]' +
#                                    re.IGNORECASE)
#                 elif priority == 'A_match':
#                     x = re.findall(e, packet_string,re.IGNORECASE)
#
#                 elif priority == 'B' or priority == 'C':
#                     x = re.findall(
#                         '.{0,' + characters_around_leak + '}[^a-z]' + e + '[^a-z]{1}.{0,' + characters_around_leak + '}',
#                         packet_string, re.IGNORECASE)
#                 if len(x) > 0:
#                     if priority in leak.LeakData.leaks_sorted_by_priority:
#                         leak.LeakData.leaks_sorted_by_priority[priority] = leak.LeakData.leaks_sorted_by_priority[priority] + x
#                     else:
#                         leak.LeakData.leaks_sorted_by_priority[priority] = x
#                     if category in leak.LeakData.leaks_sorted_by_category:
#                         leak.LeakData.leaks_sorted_by_category[category] = leak.LeakData.leaks_sorted_by_category[category] + x
#                     else:
#                         leak.LeakData.leaks_sorted_by_category[category] = x
#                     regexed_leaks.append(leak.LeakData(x, context, category, Expressions.importance_evaluations[priority]))
#                     data_found = True
#
#     if data_found:
#         return True, leak.DNSLeak('src','dst', '53', regexed_leaks)
#     else:
#         return False, None