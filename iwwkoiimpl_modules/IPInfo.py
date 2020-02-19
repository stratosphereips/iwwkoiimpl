from shodan import Shodan
from iwwkoiimpl_modules import default_parameters

class CIPInfo:
    def __init__(self):
        key = default_parameters.Values.api_key
        self.api = Shodan(key)
        self.ip_info = {}

    def get_ip_info(self, ip):
        if ip in self.ip_info:
            return self.ip_info[ip]
        else:
            info = self.api.host(ip)
            self.ip_info[ip] = info
            return info['country_name'],info['org'], info['isp'], info['ports']
