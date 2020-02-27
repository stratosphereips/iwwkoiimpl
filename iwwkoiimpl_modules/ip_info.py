from shodan import Shodan
from iwwkoiimpl_modules import parameters


# todo use different thing than shodan

class IPInfo:
    def __init__(self):
        key = parameters.Values.api_key
        self.api = Shodan(key)
        self.ip_info = {}

    def get_ip_info(self, ip):
        if ip in self.ip_info:
            return self.ip_info[ip]
        else:
            try:
                info = self.api.host(ip)
                self.ip_info[ip] = info
                return info['country_name'], info['org'], info['isp'], info['ports']
            except Exception:
                return None, None, None, None
