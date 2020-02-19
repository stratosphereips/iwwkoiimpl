from iwwkoiimpl_modules import regex




def process_sessions(sessions, leaks):
    for session in sessions:
        for packet in sessions[session]:
            try:
                # ---------- TCP ----------
                if packet.haslayer('TCP'):
                # ---------- ---------- HTTP ----------
                    if packet.haslayer('HTTP'):
                        ses = sessions[session]
                        data_found, regexed_info = regex.get_HTTP_leaks_from_session(packet)
                        if data_found:
                            leaks.append(regexed_info)

                # ---------- UDP ----------
                elif packet.haslayer('UDP'):
                    if packet.haslayer('DNS'):
                        pass
            # ---------- ---------- DNS ----------
            except IndexError:
                continue
