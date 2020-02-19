import os
from enum import IntEnum

from iwwkoiimpl_modules import default_parameters
from iwwkoiimpl_modules import IPInfo


class Context(IntEnum):
    HTTPrequest = 1
    HTTPresponse = 2
    DNSrequest = 3
    DNSresponse = 4

class LeakData:
    def __init__(self, raw_leaks: list, context: int, category: str):
        self.raw_leaks = raw_leaks
        self.context = context
        self.category = category

    def print(self):
        # todo nicer
        print(self.context, self.category, self.raw_leaks)
    def json_out(self):
        return {
            'category': self.category,
            'context': self.context,
            'raw_leaks': self.raw_leaks
        }


class Leak:
    try:
        terminal_width = os.get_terminal_size().columns
    except OSError:
        terminal_width = default_parameters.Values.terminal_width

    def print(self, ip_info: IPInfo.CIPInfo):
        pass

    def json_out(self):
        pass


class HTTPLeak(Leak):
    def __init__(self, src_ip: str, dst_ip: str, dst_port: str, request: str, user_agent: str, leaked_data: list):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.request = request
        self.user_agent = user_agent
        self.leaked_data = leaked_data

    def print(self, ip_info: IPInfo.CIPInfo):
        print('-' * self.terminal_width)
        print("From {} ----info leaking to ----> {}:{}:".format(self.src_ip, self.dst_ip, self.dst_port))

        if self.request is not None or self.user_agent is not None:
            print("header: ")
            if self.request is not None:
                print(self.request)
            if self.user_agent is not None:
                print(self.user_agent)
        print("leak:")
        for leak in self.leaked_data:
            leak.print()

        if ip_info is not None:
            try:
                country_name, org, isp, ports = ip_info.get_ip_info(self.dst_ip)
                print("Country: {}, Organization: {}, ISP: {}, Open ports:{}".format(country_name, org, isp, ports))
            except Exception as e:
                print(e)

    def json_out(self):
        dict_out = {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'dst_port': self.dst_port,
            'request': self.request,
            'user_agent': self.user_agent,
            'leaked_data': []
        }
        for i in self.leaked_data:
            dict_out['leaked_data'].append(i.json_out())

        return dict_out
