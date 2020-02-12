import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description='Get the name of a pcap.')
    parser.add_argument('-p', '--pcap_name', type = str, help = 'path to a pcap file')
    parser.add_argument('-o', '--output', type=str, help = 'csv - output to a csv file, std - print to standard output ')
    parser.add_argument('-c', '--context', type=int, help = 'how many characters to show before and after the leak found')

    args = parser.parse_args()
    if not args.pcap_name: # or not args.additional_expressions:
        parser.print_usage()
        exit(1)
    return args.pcap_name, args.output, args.context
