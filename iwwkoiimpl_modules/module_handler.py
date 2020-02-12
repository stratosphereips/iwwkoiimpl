from iwwkoiimpl_modules import regex


def process_sessions(sessions, leaks):
    for session in sessions:
        for packet in sessions[session]:
            try:
                if packet['TCP'].payload and packet['IP'].dport == 80:
                    # ---------- REGEX MODULE ----------
                    data_found, regexed_info = regex.get_leaks_from_packet(packet)
                    if data_found:
                        leaks.append(regexed_info)

            except IndexError:
                continue
