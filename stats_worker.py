import statistics
import time
from collections import defaultdict
from queue import Empty


def stats_worker_process(stats_queue, alert_queue, thresholds_dict):
    total_packets = 0
    icmp_packets = 0
    port_tracker = defaultdict(set)
    last_check = time.time()

    while True:
        timeout = max(0.0, 1.0 - (time.time() - last_check))
        try:
            event = stats_queue.get(timeout=timeout)
        except Empty:
            event = None

        if event == "STOP":
            break

        if event is not None:
            src_ip, is_icmp, dst_port = event
            total_packets += 1
            if is_icmp:
                icmp_packets += 1
            if dst_port is not None and src_ip is not None:
                port_tracker[src_ip].add(dst_port)

        now = time.time()
        if now - last_check >= 1.0:
            thresholds = dict(thresholds_dict)

            if total_packets > thresholds["ddos"]:
                alert_queue.put(("DDoS / Аномальный трафик", "Множественный",
                                  f"Трафик: {total_packets} пак/с (Порог: {thresholds['ddos']})"))
            if icmp_packets > thresholds["ping"]:
                alert_queue.put(("Ping-флуд", "Множественный",
                                  f"ICMP: {icmp_packets} пак/с (Порог: {thresholds['ping']})"))
            for ip, ports in port_tracker.items():
                if len(ports) > thresholds["ports"]:
                    alert_queue.put(("Сканирование портов", ip,
                                      f"Уникальных портов: {len(ports)} (Порог: {thresholds['ports']})"))

            total_packets = 0
            icmp_packets = 0
            port_tracker.clear()
            last_check = now


def learning_mode(duration, iface):
    from scapy.all import sniff, IP, TCP, ICMP

    print(f"Слушаю сеть {duration} секунд на интерфейсе {iface}...")
    pkts = sniff(timeout=duration, iface=iface)

    if not pkts:
        print("Трафик не обнаружен. Невозможно составить профиль.")
        return None

    traffic_per_sec = [0] * duration
    icmp_per_sec = [0] * duration
    ports_per_sec = [0] * duration
    sec_port_tracker = defaultdict(lambda: defaultdict(set))

    start_time = float(pkts[0].time)
    for p in pkts:
        sec_idx = int(float(p.time) - start_time)
        if 0 <= sec_idx < duration:
            traffic_per_sec[sec_idx] += 1
            if ICMP in p:
                icmp_per_sec[sec_idx] += 1
            if TCP in p and IP in p:
                sec_port_tracker[sec_idx][p[IP].src].add(p[TCP].dport)

    for sec in range(duration):
        if sec_port_tracker[sec]:
            ports_per_sec[sec] = max(len(ports) for ports in sec_port_tracker[sec].values())

    def _median_stdev(series):
        med = statistics.median(series)
        dev = statistics.stdev(series) if sum(series) > 0 and len(series) > 1 else 0
        return med, dev

    med_total, stdev_total = _median_stdev(traffic_per_sec)
    med_icmp, stdev_icmp = _median_stdev(icmp_per_sec)
    med_ports, stdev_ports = _median_stdev(ports_per_sec)

    thresholds = {
        "ddos": int(med_total + 3 * stdev_total) + 10,
        "ping": int(med_icmp + 3 * stdev_icmp) + 5,
        "ports": int(med_ports + 3 * stdev_ports) + 10,
    }

    print("\n[+] Профилирование завершено!")
    print(f"Общий трафик -> Медиана: {med_total} | Отклонение: {stdev_total:.2f}")
    print(f"ICMP трафик  -> Медиана: {med_icmp} | Отклонение: {stdev_icmp:.2f}")
    print(f"Скан портов  -> Медиана: {med_ports} | Отклонение: {stdev_ports:.2f}")
    print("\nРекомендуемые пороги (Медиана + 3*StDev):")
    print(f"-> DDoS: {thresholds['ddos']} пак/с")
    print(f"-> Ping: {thresholds['ping']} пак/с")
    print(f"-> Портов: {thresholds['ports']} шт/с\n")

    return thresholds
