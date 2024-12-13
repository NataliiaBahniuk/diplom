import psutil
import time
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime


class NetworkMonitor:
    def __init__(self):
        self.data = {
            'timestamp': [],
            'cpu_percent': [],
            'memory_percent': [],
            'network_bytes_sent': [],
            'network_bytes_recv': []
        }
        self.start_time = None

    def start_monitoring(self):
        """Початок моніторингу"""
        self.start_time = time.time()

    def collect_metrics(self):
        """Збір метрик"""
        if self.start_time is None:
            self.start_monitoring()

        # Збираємо метрики
        self.data['timestamp'].append(time.time() - self.start_time)
        self.data['cpu_percent'].append(psutil.cpu_percent())
        self.data['memory_percent'].append(psutil.virtual_memory().percent)

        net_io = psutil.net_io_counters()
        self.data['network_bytes_sent'].append(net_io.bytes_sent)
        self.data['network_bytes_recv'].append(net_io.bytes_recv)

    def monitor(self, duration, interval=1):
        """Моніторинг протягом вказаного часу"""
        end_time = time.time() + duration
        while time.time() < end_time:
            self.collect_metrics()
            time.sleep(interval)

    def save_to_csv(self, filename):
        """Зберігання даних у CSV файл"""
        df = pd.DataFrame(self.data)
        df.to_csv(filename, index=False)
        return filename

    def plot_metrics(self, save_path=None):
        """Візуалізація зібраних метрик"""
        fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 12))

        # CPU використання
        ax1.plot(self.data['timestamp'], self.data['cpu_percent'])
        ax1.set_title('CPU Usage')
        ax1.set_ylabel('Percent')
        ax1.grid(True)

        # Використання пам'яті
        ax2.plot(self.data['timestamp'], self.data['memory_percent'])
        ax2.set_title('Memory Usage')
        ax2.set_ylabel('Percent')
        ax2.grid(True)

        # Мережева активність
        ax3.plot(self.data['timestamp'], self.data['network_bytes_sent'],
                 label='Bytes Sent')
        ax3.plot(self.data['timestamp'], self.data['network_bytes_recv'],
                 label='Bytes Received')
        ax3.set_title('Network Activity')
        ax3.set_ylabel('Bytes')
        ax3.set_xlabel('Time (seconds)')
        ax3.legend()
        ax3.grid(True)

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path)
            return save_path
        else:
            plt.show()


class ExperimentLogger:
    def __init__(self, experiment_name):
        self.experiment_name = experiment_name
        self.log_data = []
        self.start_time = datetime.now()

    def log_event(self, event_type, description, additional_data=None):
        """Логування події"""
        event = {
            'timestamp': datetime.now(),
            'event_type': event_type,
            'description': description,
            'additional_data': additional_data
        }
        self.log_data.append(event)

    def save_log(self, filename):
        """Зберігання логу в файл"""
        with open(filename, 'w') as f:
            f.write(f"Experiment: {self.experiment_name}\n")
            f.write(f"Start Time: {self.start_time}\n")
            f.write("=" * 50 + "\n")

            for event in self.log_data:
                f.write(f"Time: {event['timestamp']}\n")
                f.write(f"Type: {event['event_type']}\n")
                f.write(f"Description: {event['description']}\n")
                if event['additional_data']:
                    f.write(f"Data: {event['additional_data']}\n")
                f.write("-" * 30 + "\n")