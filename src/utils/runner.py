import os
import json
import time
from datetime import datetime
from pathlib import Path
from ..utils.logging_config import setup_logging
from ..utils.monitoring import NetworkMonitor
from ..utils.traffic_analyzer import TrafficAnalyzer
from ..topologies import SecurityLabTopology
from ..attacks import DDoSAttack, MITMAttack, PortScanner


class ExperimentRunner:
    def __init__(self, output_dir='results'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.logger = setup_logging('experiment_runner')
        self.monitor = NetworkMonitor()
        self.analyzer = TrafficAnalyzer()

    def run_experiment(self, name, duration=300):
        """Запуск експерименту"""
        exp_dir = self.output_dir / name
        exp_dir.mkdir(exist_ok=True)

        self.logger.info(f"Starting experiment: {name}")

        # Створюємо топологію
        topo = SecurityLabTopology()
        net = topo.build()

        try:
            net.start()

            # Запускаємо моніторинг
            self.monitor.start_monitoring()

            # Запускаємо атаки
            attack_results = self._run_attacks(topo)

            # Збираємо метрики
            self.monitor.monitor(duration=duration)

            # Зберігаємо результати
            self._save_results(exp_dir, attack_results)

        finally:
            net.stop()
            self.logger.info(f"Experiment completed: {name}")

    def _run_attacks(self, topo):
        """Запуск різних типів атак"""
        results = []

        # DDoS атака
        victim = topo.get_client()
        ddos = DDoSAttack(victim)

        self.logger.info("Starting DDoS attack")
        start_time = time.time()
        ddos.start_attack()
        time.sleep(30)  # Тривалість атаки
        ddos.stop_attack()
        duration = time.time() - start_time

        results.append({
            'type': 'ddos',
            'timestamp': start_time,
            'duration': duration,
            'target': victim.IP()
        })

        # MITM атака
        attacker = topo.get_firewall()  # Використовуємо firewall як атакуючого для тесту
        victim = topo.get_client()
        gateway = topo.get_vpn_server()  # Використовуємо vpn як шлюз для тесту

        mitm = MITMAttack(attacker, victim, gateway)

        self.logger.info("Starting MITM attack")
        start_time = time.time()
        mitm.start_attack()
        time.sleep(30)  # Тривалість атаки
        mitm.stop_attack()
        duration = time.time() - start_time

        results.append({
            'type': 'mitm',
            'timestamp': start_time,
            'duration': duration,
            'target': victim.IP()
        })

        return results

    def _save_results(self, exp_dir, attack_results):
        """Збереження результатів експерименту"""
        # Зберігаємо метрики
        metrics_file = exp_dir / 'metrics.csv'
        self.monitor.save_to_csv(str(metrics_file))

        # Зберігаємо результати атак
        attacks_file = exp_dir / 'attacks.json'
        with open(attacks_file, 'w') as f:
            json.dump(attack_results, f, indent=2)

        # Генеруємо графіки
        self.monitor.plot_metrics(save_path=str(exp_dir / 'metrics.png'))

        self.logger.info(f"Results saved to {exp_dir}")


def main():
    runner = ExperimentRunner()

    # Запускаємо серію експериментів
    experiments = [
        ('baseline', 300),
        ('ddos_attack', 300),
        ('mitm_attack', 300)
    ]

    for name, duration in experiments:
        runner.run_experiment(name, duration)


if __name__ == '__main__':
    main()