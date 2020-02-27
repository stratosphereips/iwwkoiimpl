class Values:
    characters_around_leak = 20
    api_key = 'w5ibY2uMCW2GzPF8ul27rCY6rbI5GCS6'
    output_type = 'json'
    terminal_width = 10
    pcap_name = ''
    filter = 'tcp dst port 80'# or udp dst port 53'


class RegularExpressions:
    """
    Stores the regular expressions used to detect leaks.
    """
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