import os
from iwwkoiimpl_modules import IPInfo



class HTTPLeak:
    try:
        terminal_width = os.get_terminal_size().columns
    except OSError:
        terminal_width = 10
    def __init__(self,src_ip: str, dst_ip: str, dst_port : str, request: str, user_agent : str, host: str, leaked_data: list):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.request = request
        self.user_agent = user_agent
        self.host = host
        self.leaked_data = leaked_data
    def print(self, ip_info : IPInfo.CIPInfo):
        print('-' * self.terminal_width)
        print("From {} ----info leaking to ----> {}:{}:".format(self.src_ip, self.dst_ip, self.dst_port))
        if ip_info is not None:
            try:
                country_name, org, isp, ports = ip_info.get_ip_info(self.dst_ip)
                print("Country: {}, Organization: {}, ISP: {}, Open ports:{}".format(country_name, org, isp, ports))

            except Exception as e:
                print(e)
        if self.request is not None or self.user_agent is not None or self.host is not None:
            print("header: ")
            if self.request is not None:
                print(self.request)
            if self.user_agent is not None:
                print(self.user_agent)
            if self.host is not None:
                print(self.host)
        print("leak:")
        print(self.leaked_data)
