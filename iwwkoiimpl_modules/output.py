import os
import json

from iwwkoiimpl_modules.leak_store import LeakStore


def unique(input_dictionary : dict):
    """
    Takes a dictionary with duplicatie values and creates a dictionary with unique values.
    :param input_dictionary: dict
    :return: dict unique dictionary
    """
    unique_dictionary = {}
    for key, item in input_dictionary.items():
        unique_list = []
        for x in item:
            if x[0] not in unique_list:
                unique_list.append(x[0])
        unique_dictionary[key] = unique_list
    return unique_dictionary

def json_out(output_filename : str, leaks: list):
    """
    Stores a list of Leak class objects into a json in the current directory.
    :param output_filename: str
    :param leaks: list of Leak class objects
    :return: None
    """

    out_dict = {}
    for i in range(len(leaks)):
        out_dict[str(i)] = leaks[i].dic_out()

    try:
        os.mkdir(output_filename)
        with open(output_filename + '/leaks' + '.json', 'w') as json_file:
            json.dump(out_dict, json_file)
        with open(output_filename+ '/leaks'+"_priority_sorted" + '.json', 'w') as json_file:
            json.dump(unique(LeakStore.leaks_sorted_by_priority), json_file)
        with open(output_filename+ '/leaks'+"_category_sorted" + '.json', 'w') as json_file:
            json.dump(unique(LeakStore.leaks_sorted_by_category), json_file)
        with open(output_filename+ '/leaks'+"_user_agents" + '.json', 'w') as json_file:
            json.dump({"user_agents" : list(sorted(LeakStore.leaked_user_agents))}, json_file)
        with open(output_filename+ '/leaks'+"_requests" + '.json', 'w') as json_file:
            json.dump({"user_agents" : list(sorted(LeakStore.leaked_requests))} , json_file)
        with open(output_filename + '/leaks'+ "_ner" + '.json', 'w') as json_file:
            json.dump(LeakStore.leaks_based_on_ner, json_file)
    except IOError as e:
        print("I/O error")


def std_out(leaks: list, display_ip_info: bool):
    """
    Formats and prints the list of Leak class objects to std ouptut.
    :param leaks: list of Leak class objects
    :param display_ip_info: bool true if it should print the IP info to std
    :return:
    """
    # todo nicer
    out_dict = {}
    for i in range(len(leaks)):
        out_dict[str(i)] = leaks[i].json_out()
    print(out_dict)

