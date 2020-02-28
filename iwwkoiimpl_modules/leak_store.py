from iwwkoiimpl_modules import ner


class LeakStore:
    """
    Initializes necessary things for the detection modules.
    Stores detected leaked data.
    """
    leaks = []

    leaks_sorted_by_priority = {}
    leaks_sorted_by_category = {}
    leaked_user_agents = set()
    leaked_requests = set()
    leaks_based_on_ner = {}

    ner_detector = ner.NERLeakDetector()