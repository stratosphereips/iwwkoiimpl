import csv
from datetime import date
from iwwkoiimpl_modules import leak
from iwwkoiimpl_modules import IPInfo


def out(leaks: list, output_type: str, output_filename=None, display_ip_info=True):
    if output_type == 'csv':
        if output_filename is None:
            output_filename = 'leak_' + date.today().strftime("%d_%m_%Y") + '.csv'
        csv_out(leaks, output_filename)
    if output_type == 'std':
        std_out(leaks, display_ip_info)


def csv_out(leaks: list,output_filename):
    try:
        a_file = open(output_filename, "w")
        writer = csv.writer(a_file, quoting=csv.QUOTE_ALL)
        for l in leaks:
            writer.writerow(l.csv_out())
    except IOError:
        print("I/O error")


def std_out(leaks: list, display_ip_info: bool):

    if display_ip_info:
        ip_info = IPInfo.CIPInfo()
    else:
        ip_info = None
    for packet_leak in leaks:
        if display_ip_info:
            packet_leak.print(ip_info)
