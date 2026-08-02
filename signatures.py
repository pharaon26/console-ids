import json

from scapy.all import IP, TCP


def _cond_ip_self_reference(pkt, rule):
    return IP in pkt and pkt[IP].src == pkt[IP].dst


def _cond_tcp_flags_equal(pkt, rule):
    if TCP not in pkt:
        return False
    return pkt[TCP].flags == rule["value"]


CONDITION_HANDLERS = {
    "ip_self_reference": _cond_ip_self_reference,
    "tcp_flags_equal": _cond_tcp_flags_equal,
}


class SignatureEngine:
    def __init__(self, rules_path):
        with open(rules_path, "r", encoding="utf-8") as f:
            self.rules = json.load(f)

    def check(self, pkt):
        matches = []
        for rule in self.rules:
            handler = CONDITION_HANDLERS.get(rule["condition"])
            if handler and handler(pkt, rule):
                matches.append(rule)
        return matches
