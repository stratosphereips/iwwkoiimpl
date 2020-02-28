from shodan import Shodan
from iwwkoiimpl_modules import parameters


# todo use different thing than shodan

class IPInfo:
    """
    Stores destination IPs and gathers information about them.
    """
    def __init__(self):
        """
        Initializes the api and a dictionary that stores IPs and their info.
        """
        key = parameters.Values.api_key
        self.api = Shodan(key)
        self.ip_info = {}

    def get_ip_info(self, ip):
        """
        Gets information for an IP.
        :param ip: str IP to look up
        :return: country of IP, Autonomous system, ISP, ...
        """
        if ip in self.ip_info:
            return self.ip_info[ip]
        else:
            try:
                info = self.api.host(ip)
                self.ip_info[ip] = info
                return info['country_name'], info['org'], info['isp'], info['ports']
            except Exception:
                return None, None, None, None
