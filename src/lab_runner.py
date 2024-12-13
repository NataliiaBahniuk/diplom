from mininet.log import setLogLevel, info
from topologies import SecurityLabTopology
from security import Firewall, IDS, VPNManager
import time
import signal
import sys


class LabRunner:
    def __init__(self):
        self.topo = None
        self.services = {}
        setLogLevel('info')

    def setup_network(self):
        """Налаштування мережевої топології"""
        info('*** Створення мережевої топології\n')
        self.topo = SecurityLabTopology()
        self.topo.build()

    def setup_security(self):
        """Налаштування компонентів безпеки"""
        info('*** Налаштування компонентів безпеки\n')

        # Налаштування файрвола
        firewall_node = self.topo.get_firewall()
        fw = Firewall(firewall_node)
        fw.load_rules_from_file('/app/configs/firewall/rules.json')
        fw.apply_rules()
        self.services['firewall'] = fw

        # Налаштування IDS
        ids_node = self.topo.get_ids()
        ids = IDS(ids_node)
        ids.configure('/app/configs/ids/snort.conf')
        ids.start_monitoring('ids-eth0')
        self.services['ids'] = ids

        # Налаштування VPN
        vpn_node = self.topo.get_vpn_server()
        vpn = VPNManager(vpn_node)
        vpn.setup('/app/configs/vpn/openvpn.conf')
        vpn.start_server()
        self.services['vpn'] = vpn

    def start(self):
        """Запуск лабораторії"""
        try:
            self.setup_network()
            self.topo.start()
            self.setup_security()

            info('*** Лабораторія запущена та готова до роботи\n')
            info('*** Натисніть Ctrl+C для завершення\n')

            # Очікуємо сигнал завершення
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.pause()

        except Exception as e:
            info(f'*** Помилка запуску лабораторії: {e}\n')
            self.cleanup()
            sys.exit(1)

    def cleanup(self):
        """Очищення ресурсів"""
        info('*** Зупинка сервісів\n')

        if 'ids' in self.services:
            self.services['ids'].stop_monitoring()

        if 'vpn' in self.services:
            self.services['vpn'].stop_server()

        if self.topo:
            self.topo.stop()

    def signal_handler(self, sig, frame):
        """Обробник сигналу завершення"""
        info('\n*** Отримано сигнал завершення\n')
        self.cleanup()
        sys.exit(0)


if __name__ == '__main__':
    runner = LabRunner()
    runner.start()