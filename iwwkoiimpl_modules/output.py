import csv
from time import gmtime, strftime
import json

from iwwkoiimpl_modules import leak
from iwwkoiimpl_modules import IPInfo
from iwwkoiimpl_modules import leak_handler


def unique(input_dictionary : dict):
    unique_dictionary = {}
    for key, item in input_dictionary.items():
        unique_list = []
        for x in item:
            if x not in unique_list:
                unique_list.append(x)
        unique_dictionary[key]=unique_list
    return unique_dictionary

# def out(leaks: list, output_type: str, output_filename=None, display_ip_info=True):
#     a = leak.LeakData.leaked_based_on_ner
#     if output_type == 'json':
#         if output_filename is None:
#             output_filename = 'leaks_from_' + strftime("%Y-%m-%d_%H:%M:%S", gmtime())
#         json_out(leaks, output_filename)
#     if output_type == 'std':
#         std_out(leaks, display_ip_info)


def json_out(output_filename, leaks: list):
    out_dict = {}
    for i in range(len(leaks)):
        out_dict[str(i)] = leaks[i].dic_out()

    try:
        with open(output_filename, 'w') as json_file:
            json.dump(out_dict, json_file)
        # with open(output_filename+"_priority_sorted" + '.json', 'w') as json_file:
        #     json.dump(unique(leak.LeakData.leaks_sorted_by_priority), json_file)
        # with open(output_filename+"_category_sorted" + '.json', 'w') as json_file:
        #     json.dump(unique(leak.LeakData.leaks_sorted_by_category), json_file)
        # with open(output_filename+"_user_agents" + '.json', 'w') as json_file:
        #     json.dump({"user_agents" : list(sorted(leak.LeakData.leaked_user_agents))}, json_file)
        # with open(output_filename+"_requests" + '.json', 'w') as json_file:
        #     json.dump({"user_agents" : list(sorted(leak.LeakData.leaked_requests))} , json_file)
        # with open(output_filename + "_ner" + '.json', 'w') as json_file:
        #     json.dump(unique(leak.LeakData.leaked_based_on_ner), json_file)




    except IOError as e:
        print(e)

        print("I/O error")


def std_out(leaks: list, display_ip_info: bool):
    out_dict = {}
    for i in range(len(leaks)):
        out_dict[str(i)] = leaks[i].json_out()

    print(out_dict)

