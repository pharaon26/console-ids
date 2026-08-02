from scapy.all import AsyncSniffer, IP, TCP, ICMP


def make_packet_handler(signature_engine, alert_logger, stats_queue):
    def handle_packet(pkt):
        for rule in signature_engine.check(pkt):
            src_ip = pkt[IP].src if IP in pkt else "Неизвестно"
            alert_logger.log_alert(rule["severity"], src_ip, rule["name"])

        src_ip = pkt[IP].src if IP in pkt else None
        is_icmp = ICMP in pkt
        dst_port = pkt[TCP].dport if TCP in pkt else None
        stats_queue.put((src_ip, is_icmp, dst_port))

    return handle_packet


def start_sniffer(iface, handler):
    sniffer = AsyncSniffer(iface=iface, prn=handler, store=False)
    sniffer.start()
    return sniffer
