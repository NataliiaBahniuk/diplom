import os
import subprocess
from mininet.log import info
import re
import time
from threading import Thread
import queue


class IDS:
    def __init__(self, node):
        """
        Ініціалізація системи виявлення вторгнень
        :param node: Mininet хост для запуску IDS
        """
        self.node = node
        self.alerts_queue = queue.Queue()
        self.is_monitoring = False
        self.monitor_thread = None

    def configure(self, config_file):
        """
        Налаштування Snort з конфігураційного файлу
        :param config_file: шлях до конфігураційного файлу
        """
        # Перевіряємо наявність конфігураційного файлу
        if not os.path.exists(config_file):
            info(f'*** Error: Configuration file {config_file} not found\n')
            return False

        try:
            # Копіюємо конфігураційний файл на хост
            self.node.cmd(f'mkdir -p /etc/snort')
            self.node.cmd(f'cp {config_file} /etc/snort/snort.conf')

            # Тестуємо конфігурацію
            result = self.node.cmd('snort -T -c /etc/snort/snort.conf')
            if 'Failed' in result or 'Error' in result:
                info(f'*** Error in Snort configuration: {result}\n')
                return False

            info('*** IDS configured successfully\n')
            return True
        except Exception as e:
            info(f'*** Error configuring IDS: {e}\n')
            return False

    def start_monitoring(self, interface):
        """
        Запуск моніторингу на вказаному інтерфейсі
        :param interface: мережевий інтерфейс для моніторингу
        """
        if self.is_monitoring:
            info('*** IDS is already running\n')
            return False

        try:
            # Запускаємо Snort в режимі IDS
            command = f'snort -A console -i {interface} -c /etc/snort/snort.conf -l /var/log/snort'
            self.node.cmd(f'{command} > /var/log/snort/alerts.log 2>&1 &')

            # Запускаємо моніторинг алертів
            self.is_monitoring = True
            self.monitor_thread = Thread(target=self._monitor_alerts)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

            info(f'*** IDS started monitoring on {interface}\n')
            return True
        except Exception as e:
            info(f'*** Error starting IDS: {e}\n')
            return False

    def stop_monitoring(self):
        """Зупинка моніторингу"""
        if not self.is_monitoring:
            return

        try:
            self.is_monitoring = False
            self.node.cmd('pkill snort')
            if self.monitor_thread:
                self.monitor_thread.join(timeout=2)
            info('*** IDS monitoring stopped\n')
        except Exception as e:
            info(f'*** Error stopping IDS: {e}\n')

    def _monitor_alerts(self):
        """Моніторинг файлу алертів"""
        alert_pattern = re.compile(r'\[\*\*\] \[(.*?)\] (.*?) \[\*\*\]')

        while self.is_monitoring:
            try:
                alerts = self.node.cmd('tail -n 1 /var/log/snort/alerts.log')
                for line in alerts.splitlines():
                    match = alert_pattern.search(line)
                    if match:
                        alert = {
                            'signature_id': match.group(1),
                            'description': match.group(2),
                            'timestamp': time.time(),
                            'raw': line
                        }
                        self.alerts_queue.put(alert)
            except Exception as e:
                info(f'*** Error monitoring alerts: {e}\n')
            time.sleep(1)

    def get_alerts(self, max_alerts=10):
        """
        Отримання останніх алертів
        :param max_alerts: максимальна кількість алертів
        :return: список алертів
        """
        alerts = []
        try:
            while len(alerts) < max_alerts and not self.alerts_queue.empty():
                alerts.append(self.alerts_queue.get_nowait())
        except queue.Empty:
            pass
        return alerts

    def add_rule(self, rule):
        """
        Додавання нового правила виявлення
        :param rule: правило Snort
        """
        try:
            with open('/etc/snort/rules/local.rules', 'a') as f:
                f.write(f'\n{rule}')

            # Перезавантажуємо правила
            self.node.cmd('kill -SIGHUP $(pidof snort)')
            info(f'*** Added new IDS rule: {rule}\n')
            return True
        except Exception as e:
            info(f'*** Error adding IDS rule: {e}\n')
            return False

    def get_statistics(self):
        """Отримання статистики роботи IDS"""
        try:
            stats = self.node.cmd('snort_stat /var/log/snort/snort.stats')
            return stats
        except Exception as e:
            info(f'*** Error getting IDS statistics: {e}\n')
            return None