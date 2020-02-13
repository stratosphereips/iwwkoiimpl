import argparse

from iwwkoiimpl_modules import default_parameters

def parse_arguments():
    parser = argparse.ArgumentParser(description='Get the name of a pcap.')
    parser.add_argument('-p', '--pcap_name', type = str, help = 'path to a pcap file')
    parser.add_argument('-o', '--output', type=str, help = 'csv - output to a csv file, std - print to standard output ')
    parser.add_argument('-c', '--context', type=int, help = 'how many characters to show before and after the leak found')

    args = parser.parse_args()
    if args.pcap_name is None:
        parser.print_usage()
        raise Exception("argument error")
    if args.output is not None and args.output != 'std' and args.output != 'csv':
        print("Wrong output format, setting to default:", default_parameters.CDefaultParameters.output)
        args.output = 'std'

    return args.pcap_name, args.output, args.context
