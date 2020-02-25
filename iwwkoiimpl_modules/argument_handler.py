import argparse

from iwwkoiimpl_modules.parameters import Values

def parse_arguments():
    """
    Gets pcap name, output type and number of characters around leak and rewrites the default values.
    :return: None
    """
    parser = argparse.ArgumentParser(description='Hi there, this is iwwkoiimpl and this is how you use it.')
    parser.add_argument('-p', '--pcap_name', type = str, help = 'path to a pcap file')
    parser.add_argument('-o', '--output', type=str, help = 'json - output to a json file, std - print to standard output ')
    parser.add_argument('-c', '--characters_around_leak', type=int, help = 'how many characters to show before and after the leak found')

    args = parser.parse_args()
    if args.pcap_name is None:
        parser.print_usage()
        # todo error and usage
        Values.pcap_name=''
        # raise Exception("argument error")

    if args.output is not None and args.output != 'std' and args.output != 'json':
        print("Wrong output format, setting to default:", Values.output_type)

    if args.characters_around_leak is not None:
        Values.characters_around_leak = args.characters_around_leak

