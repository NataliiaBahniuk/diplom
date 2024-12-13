import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import json


class ExperimentAnalyzer:
    def __init__(self, results_dir):
        self.results_dir = Path(results_dir)
        self.data = {}

    def load_experiment_data(self, experiment_name):
        """Завантаження даних експерименту"""
        exp_path = self.results_dir / experiment_name

        # Завантаження метрик
        metrics_file = exp_path / 'metrics.csv'
        if metrics_file.exists():
            self.data['metrics'] = pd.read_csv(metrics_file)

        # Завантаження результатів атак
        attacks_file = exp_path / 'attacks.json'
        if attacks_file.exists():
            with open(attacks_file, 'r') as f:
                self.data['attacks'] = json.load(f)

        # Завантаження логів IDS
        ids_file = exp_path / 'ids_alerts.csv'
        if ids_file.exists():
            self.data['ids_alerts'] = pd.read_csv(ids_file)

    def analyze_network_performance(self):
        """Аналіз продуктивності мережі"""
        if 'metrics' not in self.data:
            return None

        metrics = self.data['metrics']

        analysis = {
            'bandwidth': {
                'mean': metrics['bandwidth'].mean(),
                'max': metrics['bandwidth'].max(),
                'min': metrics['bandwidth'].min()
            },
            'latency': {
                'mean': metrics['latency'].mean(),
                'max': metrics['latency'].max(),
                'min': metrics['latency'].min()
            },
            'packet_loss': metrics['packet_loss'].mean()
        }

        return analysis

    def analyze_attacks(self):
        """Аналіз результатів атак"""
        if 'attacks' not in self.data:
            return None

        attacks = self.data['attacks']

        analysis = {
            'total_attacks': len(attacks),
            'successful_attacks': sum(1 for a in attacks if a['success']),
            'attack_types': {},
            'average_duration': sum(a['duration'] for a in attacks) / len(attacks)
        }

        for attack in attacks:
            attack_type = attack['type']
            if attack_type not in analysis['attack_types']:
                analysis['attack_types'][attack_type] = 0
            analysis['attack_types'][attack_type] += 1

        return analysis

    def analyze_ids_effectiveness(self):
        """Аналіз ефективності IDS"""
        if 'attacks' not in self.data or 'ids_alerts' not in self.data:
            return None

        attacks = self.data['attacks']
        alerts = self.data['ids_alerts']

        true_positives = sum(1 for alert in alerts if any(
            self._match_alert_to_attack(alert, attack) for attack in attacks
        ))

        false_positives = len(alerts) - true_positives
        false_negatives = sum(1 for attack in attacks if not any(
            self._match_alert_to_attack(alert, attack) for alert in alerts
        ))

        analysis = {
            'true_positives': true_positives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'precision': true_positives / (true_positives + false_positives),
            'recall': true_positives / (true_positives + false_negatives)
        }

        return analysis

    def _match_alert_to_attack(self, alert, attack):
        """Співставлення алерту з атакою"""
        return (
                abs(alert['timestamp'] - attack['timestamp']) < 5 and
                alert['type'] == attack['type']
        )

    def generate_plots(self, output_dir):
        """Генерація графіків"""
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)

        if 'metrics' in self.data:
            self._plot_network_metrics(output_dir)

        if 'attacks' in self.data and 'ids_alerts' in self.data:
            self._plot_attack_detection(output_dir)

    def _plot_network_metrics(self, output_dir):
        """Створення графіків мережевих метрик"""
        metrics = self.data['metrics']

        # Графік використання пропускної здатності
        plt.figure(figsize=(12, 6))
        sns.lineplot(data=metrics, x='timestamp', y='bandwidth')
        plt.title('Network Bandwidth Usage')
        plt.savefig(output_dir / 'bandwidth.png')
        plt.close()

        # Графік затримки
        plt.figure(figsize=(12, 6))
        sns.lineplot(data=metrics, x='timestamp', y='latency')
        plt.title('Network Latency')
        plt.savefig(output_dir / 'latency.png')
        plt.close()

    def _plot_attack_detection(self, output_dir):
        """Створення графіків виявлення атак"""
        attacks = pd.DataFrame(self.data['attacks'])
        alerts = self.data['ids_alerts']

        # Графік розподілу типів атак
        plt.figure(figsize=(10, 6))
        attacks['type'].value_counts().plot(kind='bar')
        plt.title('Attack Type Distribution')
        plt.savefig(output_dir / 'attack_types.png')
        plt.close()

        # Графік ефективності IDS
        analysis = self.analyze_ids_effectiveness()
        plt.figure(figsize=(8, 8))
        labels = ['True Positives', 'False Positives', 'False Negatives']
        sizes = [analysis['true_positives'],
                 analysis['false_positives'],
                 analysis['false_negatives']]
        plt.pie(sizes, labels=labels, autopct='%1.1f%%')
        plt.title('IDS Effectiveness')
        plt.savefig(output_dir / 'ids_effectiveness.png')
        plt.close()