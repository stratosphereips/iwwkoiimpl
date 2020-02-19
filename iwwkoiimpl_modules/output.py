import csv
from datetime import date
import json

from iwwkoiimpl_modules import leak
from iwwkoiimpl_modules import IPInfo


def out(leaks: list, output_type: str, output_filename=None, display_ip_info=True):
    if output_type == 'json':
        if output_filename is None:
            output_filename = 'leak_' + date.today().strftime("%H%M%S_%d_%m_%Y") + '.json'
        json_out(leaks, output_filename)
    if output_type == 'std':
        std_out(leaks, display_ip_info)


def json_out(leaks: list, output_filename):
    out_dict = {}
    for i in range(len(leaks)):
        out_dict[str(i)]=leaks[i].json_out()

    try:
        with open(output_filename, 'w') as json_file:
            json.dump(out_dict, json_file)

    except IOError:
        print("I/O error")


def std_out(leaks: list, display_ip_info: bool):

    if display_ip_info:
        ip_info = IPInfo.CIPInfo()
    else:
        ip_info = None

    #todo print the info here somehow

    for packet_leak in leaks:
        if display_ip_info:
            packet_leak.print(ip_info)
