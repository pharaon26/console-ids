# lo0 - macOS, lo - Linux, для Windows см. scapy.arch.get_windows_if_list()
NETWORK_INTERFACE = "lo0"

DEFAULT_THRESHOLDS = {
    "ddos": 1000,   # пак/с
    "ping": 100,    # ICMP пак/с
    "ports": 50,    # уникальных портов/с
}

SIGNATURES_FILE = "signatures.json"
ALERTS_LOG_FILE = "alerts.csv"

ALERT_COOLDOWN_SECONDS = 5  # не долбить одинаковыми алертами чаще раза в N сек
TABLE_HISTORY_SIZE = 15
