import os
from enum import IntEnum

from iwwkoiimpl_modules import parameters
from iwwkoiimpl_modules.ip_info import IPInfo


class Context:
    """
    Stores strings that identify context of the given leak.
    """
    HTTP = 'HTTP'
    HTTPRequest = 'HTTPRequest'
    HTTPResponse = 'HTTPResponse'
    DNS = 'DNS'
    DNSRequest = 'DNSRequest'
    DNSResponse = 'DNSResponse'

class LeakData:
    """
    Stores the detected leaked strings of one category and priority.
    """
    def __init__(self, raw_leaks: list, category: str, priority: float):
        """
        Stores list of leaks, their category and priority.
        :param raw_leaks: list
        :param category: str
        :param priority: str
        """
        self.raw_leaks = raw_leaks
        self.category = category
        self.priority = priority

    def dic_out(self):
        """
        Returns a dictionary with the stored values.
        :return: dict
        """
        return {
            'category': self.category,
            'priority': self.priority,
            'raw_leaks': self.raw_leaks
        }


class Leak:
    """
    Parent class that stores information about all leaks from a packet and a list of LeakData.
    """
    def print(self):
        pass

    def dic_out(self):
        pass


class HTTPLeak(Leak):
    """
    Child class of Leak that stores additional information specific for the HTTP protocol.
    """
    def __init__(self, src_ip: str, dst_ip: str, dst_port: str, request: str, user_agent: str, context : int, leaked_data: list):
        """
        Constructor stores information about the packet that carried leaked data.
        :param src_ip: str
        :param dst_ip: str
        :param dst_port: str
        :param request: str The whole request
        :param user_agent: The entire User-Agent
        :param context: str String specifying the context of the leak, see the Context class.
        :param leaked_data: list of LeakData objects.
        """
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.request = request
        self.user_agent = user_agent
        self.context = context
        self.leaked_data = leaked_data

    def print(self):
        """
        Prints information about the leak to the standard output.
        :return: None
        """
        try:
            terminal_width = os.get_terminal_size().columns
        except OSError:
            terminal_width = parameters.Values.terminal_width

        print('-' * terminal_width)
        print("From {} ----info leaking to ----> {}:{}:".format(self.src_ip, self.dst_ip, self.dst_port))

        # print only the data that were found
        if self.request is not None or self.user_agent is not None:
            print("header: ")
            if self.request is not None:
                print(self.request)
            if self.user_agent is not None:
                print(self.user_agent)

        print("leak:")
        for leak in self.leaked_data:
            leak.print()

        country_name, org, isp, ports = IPInfo.get_ip_info(self.dst_ip)
        if country_name is not None:
            print("Country: {}, Organization: {}, ISP: {}, Open ports:{}".format(country_name, org, isp, ports))

    def dic_out(self):
        """
        Transforms the object into a dictionary and returns it.
        :return: dict
        """
        dict_out = {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'dst_port': self.dst_port,
            'request': self.request,
            'user_agent': self.user_agent,
            'context': self.context,
            'leaked_data': []
        }
        for i in self.leaked_data:
            dict_out['leaked_data'].append(i.dic_out())

        return dict_out

class DNSLeak(Leak):
    """
    Child class of Leak class that stores additional information specific for the DNS protocol.
    """
    def __init__(self, src_ip: str, dst_ip: str, dst_port: str, leaked_data: list):
        """
        Constructor stores information about the DNS packet that carried leaked data.
        :param src_ip: str
        :param dst_ip: str
        :param dst_port: str
        :param leaked_data: list of of LeakData objects
        """
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.leaked_data = leaked_data

    def dic_out(self):
        """
        Transforms the object into a dictionary and returns it.
        :return: dict
        """
        dict_out = {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'dst_port': self.dst_port,
            'leaked_data': []
        }
        for i in self.leaked_data:
            dict_out['leaked_data'].append(i.dic_out())

        return dict_out
