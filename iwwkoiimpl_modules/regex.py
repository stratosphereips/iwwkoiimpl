import re
from typing import Match

from iwwkoiimpl_modules import leak
from iwwkoiimpl_modules import parameters
from iwwkoiimpl_modules.parameters import RegularExpressions
from iwwkoiimpl_modules.leak_store import LeakStore


def get_specific_leaks(packet_string, category: str) -> [bool, list]:
    """
    Extract leaks from input string using specified category of regular expressions.
    :param packet_string: str
    :param category: str
    :return: [bool, list]
    """
    regexed_leaks = []  # list of LeakData
    for e in RegularExpressions.regex_templates['specific'][category]:
        x = re.findall(e, packet_string, re.IGNORECASE)
        if len(x) > 0:
            regexed_leaks.append(leak.LeakData(x, category, 1.))
    return len(regexed_leaks) > 0, regexed_leaks


def get_leaks(packet_string: str) -> [bool, list]:
    """
    Extracts leaks using regular expressions.
    :param packet: str
    :return [bool, list]
    """
    characters_around_leak = str(parameters.Values.characters_around_leak)
    regexed_leaks = []  # list of LeakData

    for priority, i in RegularExpressions.regex_templates.items():
        for category, expressions in i.items():
            if priority == 'specific':
                continue
            for e in expressions:
                x = []
                if priority == 'A_field':
                    for i in re.finditer(e + '.?[=:/].{0,' + characters_around_leak + '}', packet_string, re.IGNORECASE):
                        x.append([str(i.group()), int(i.start()), int(i.end())])
                        # print(type(i.group()))
                    # x = re.findall(e + '.?[=:/].{0,' + characters_around_leak + '}', packet_string, re.IGNORECASE)
                elif priority == 'A_match':
                    # x = re.findall(e, packet_string, re.IGNORECASE)
                    for i in re.finditer(e, packet_string, re.IGNORECASE):
                        x.append([str(i.group()), int(i.start()), int(i.end())])

                elif priority == 'B' or priority == 'C':
                    # x = re.findall('.{0,' + characters_around_leak + '}[^a-z]' + e + '[^a-z]{1}.{0,' + characters_around_leak + '}', packet_string, re.IGNORECASE)
                    for i in re.finditer('.{0,' + characters_around_leak + '}[^a-z]' + e + '[^a-z]{1}.{0,' + characters_around_leak + '}', packet_string, re.IGNORECASE):
                        x.append([str(i.group()), int(i.start()), int(i.end())])
                if len(x) > 0:
                    if priority in LeakStore.leaks_sorted_by_priority:
                        LeakStore.leaks_sorted_by_priority[priority] = LeakStore.leaks_sorted_by_priority[priority] + x
                    else:
                        LeakStore.leaks_sorted_by_priority[priority] = x
                    if category in LeakStore.leaks_sorted_by_category:
                        LeakStore.leaks_sorted_by_category[category] = LeakStore.leaks_sorted_by_category[category] + x
                    else:
                        LeakStore.leaks_sorted_by_category[category] = x
                    regexed_leaks.append(leak.LeakData(x, category, RegularExpressions.importance_evaluations[priority]))

    return len(regexed_leaks) > 0, regexed_leaks
