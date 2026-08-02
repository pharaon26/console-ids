import csv
import os
import time
from collections import deque
from datetime import datetime

from rich.console import Console
from rich.live import Live
from rich.table import Table

from config import ALERTS_LOG_FILE, ALERT_COOLDOWN_SECONDS, TABLE_HISTORY_SIZE

console = Console()


class AlertLogger:
    def __init__(self):
        self.history = deque(maxlen=TABLE_HISTORY_SIZE)
        self._last_seen = {}  # (ip, threat_type) -> время последнего алерта
        self.live = None
        self._ensure_csv_header()

    def _ensure_csv_header(self):
        if not os.path.exists(ALERTS_LOG_FILE):
            with open(ALERTS_LOG_FILE, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(["Время", "IP Источника", "Тип угрозы", "Детали инцидента"])

    def _on_cooldown(self, source_ip, threat_type):
        key = (source_ip, threat_type)
        last = self._last_seen.get(key)
        now = time.time()
        if last is not None and now - last < ALERT_COOLDOWN_SECONDS:
            return True
        self._last_seen[key] = now
        return False

    def log_alert(self, threat_type, source_ip, details):
        if self._on_cooldown(source_ip, threat_type):
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.history.append((timestamp, source_ip, threat_type, details))

        if self.live:
            self.live.update(self._generate_table())

        with open(ALERTS_LOG_FILE, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([timestamp, source_ip, threat_type, details])

    def _generate_table(self):
        table = Table(title="[bold green]IDS Система обнаружения вторжений[/bold green]", style="cyan")
        table.add_column("Время", justify="center", style="dim", width=20)
        table.add_column("IP Источника", style="magenta", justify="center", width=18)
        table.add_column("Тип угрозы", style="red", justify="center", width=25)
        table.add_column("Детали инцидента", justify="left", style="green")
        for row in self.history:
            table.add_row(*row)
        return table

    def run_live(self, refresh_per_second=4):
        self.live = Live(self._generate_table(), refresh_per_second=refresh_per_second)
        return self.live
