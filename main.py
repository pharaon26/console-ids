import multiprocessing as mp
from queue import Empty

from config import NETWORK_INTERFACE, DEFAULT_THRESHOLDS, SIGNATURES_FILE
from signatures import SignatureEngine
from logger import AlertLogger
from capture import make_packet_handler, start_sniffer
from stats_worker import stats_worker_process, learning_mode


def setup_thresholds(thresholds_dict):
    print("\n--- НАСТРОЙКА ПАРАМЕТРОВ ---")
    labels = {
        "ddos": "DDoS (пакетов/с)",
        "ping": "Ping-флуд (ICMP/с)",
        "ports": "Скан портов (шт/с)",
    }
    for key, desc in labels.items():
        val = input(f"Введите порог для {desc} [Текущий: {thresholds_dict[key]}]: ")
        if val.isdigit():
            thresholds_dict[key] = int(val)


def run_monitoring(thresholds_dict):
    signature_engine = SignatureEngine(SIGNATURES_FILE)
    alert_logger = AlertLogger()

    stats_queue = mp.Queue()
    alert_queue = mp.Queue()

    stats_proc = mp.Process(
        target=stats_worker_process,
        args=(stats_queue, alert_queue, thresholds_dict),
        daemon=True,
    )
    stats_proc.start()

    handler = make_packet_handler(signature_engine, alert_logger, stats_queue)
    sniffer = start_sniffer(NETWORK_INTERFACE, handler)

    print("\n[+] Мониторинг запущен. Для остановки нажмите Ctrl+C...")

    try:
        with alert_logger.run_live():
            while True:
                try:
                    threat_type, source_ip, details = alert_queue.get(timeout=0.25)
                    alert_logger.log_alert(threat_type, source_ip, details)
                except Empty:
                    continue
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        stats_queue.put("STOP")
        stats_proc.join(timeout=2)
        alert_logger.live = None
        print("\n[-] Мониторинг остановлен. Логи сохранены в alerts.csv")


def main():
    thresholds_dict = mp.Manager().dict(DEFAULT_THRESHOLDS)

    while True:
        print("\n=== Console IDS ===")
        print(
            f"Текущие пороги: DDoS={thresholds_dict['ddos']}, "
            f"Ping={thresholds_dict['ping']}, Ports={thresholds_dict['ports']}"
        )
        print("1. Настроить пороги")
        print("2. Запустить умное профилирование")
        print("3. Запустить мониторинг")
        print("4. Выход")

        choice = input("Выберите действие: ")

        if choice == "1":
            setup_thresholds(thresholds_dict)
        elif choice == "2":
            try:
                duration = int(input("Введите время профилирования в секундах (минимум 3): "))
                duration = max(duration, 3)
            except ValueError:
                duration = 10
            new_thresholds = learning_mode(duration, NETWORK_INTERFACE)
            if new_thresholds:
                thresholds_dict.update(new_thresholds)
        elif choice == "3":
            run_monitoring(thresholds_dict)
        elif choice == "4":
            print("Завершение работы.")
            break
        else:
            print("Неизвестная команда.")


if __name__ == "__main__":
    main()
