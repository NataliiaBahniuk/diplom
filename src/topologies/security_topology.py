from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


class SecurityTopology:
    def __init__(self):
        self.net = None
        self.client = None
        self.server = None
        self.firewall = None
        self.ids = None
        self.vpn = None

    def build(self):
        """Створення топології з елементами безпеки"""
        self.net = Mininet(
            controller=Controller,
            switch=OVSKernelSwitch,
            link=TCLink
        )

        info('*** Додаємо контролер\n')
        self.net.addController('c0')

        info('*** Додаємо комутатори\n')
        s1 = self.net.addSwitch('s1')  # Внутрішня мережа
        s2 = self.net.addSwitch('s2')  # DMZ
        s3 = self.net.addSwitch('s3')  # Зовнішня мережа

        info('*** Додаємо хости\n')
        # Клієнтські хости
        self.client = self.net.addHost(
            'client',
            ip='10.0.1.10/24',
            defaultRoute='via 10.0.1.1'
        )
        self.server = self.net.addHost(
            'server',
            ip='10.0.1.100/24',
            defaultRoute='via 10.0.1.1'
        )

        # Компоненти безпеки
        self.firewall = self.net.addHost(
            'firewall',
            ip='10.0.0.1/24'
        )
        self.ids = self.net.addHost(
            'ids',
            ip='10.0.0.2/24'
        )
        self.vpn = self.net.addHost(
            'vpn',
            ip='10.0.0.3/24'
        )

        info('*** Створюємо з\'єднання\n')
        # Підключення внутрішньої мережі
        self.net.addLink(
            self.client,
            s1,
            bw=10,
            delay='2ms'
        )
        self.net.addLink(
            self.server,
            s1,
            bw=100,
            delay='1ms'
        )

        # Підключення компонентів безпеки
        self.net.addLink(
            self.firewall,
            s1,
            bw=1000,
            delay='0.1ms'
        )
        self.net.addLink(
            self.firewall,
            s2,
            bw=1000,
            delay='0.1ms'
        )
        self.net.addLink(
            self.ids,
            s2,
            bw=1000,
            delay='0.1ms'
        )
        self.net.addLink(
            self.vpn,
            s2,
            bw=100,
            delay='1ms'
        )

        # Підключення до зовнішньої мережі
        self.net.addLink(s2, s3)

        return self.net

    def configure_security(self):
        """Налаштування компонентів безпеки"""
        info('*** Налаштування Firewall\n')
        self.firewall.cmd('sysctl -w net.ipv4.ip_forward=1')
        # Базові правила firewall
        self.firewall.cmd('iptables -F')
        self.firewall.cmd('iptables -P FORWARD DROP')
        self.firewall.cmd('iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT')

        info('*** Налаштування IDS\n')
        self.ids.cmd('touch /var/log/snort/alert')
        self.ids.cmd('snort -D -c /etc/snort/snort.conf')

        info('*** Налаштування VPN\n')
        self.vpn.cmd('openvpn --config /etc/openvpn/server.conf &')

    def start(self):
        """Запуск мережі"""
        if self.net is None:
            self.build()

        info('*** Запускаємо мережу\n')
        self.net.start()

        info('*** Налаштовуємо компоненти безпеки\n')
        self.configure_security()

        info('*** Перевіряємо з\'єднання\n')
        self.net.pingAll()

        info('*** Запускаємо CLI\n')
        CLI(self.net)

    def stop(self):
        """Зупинка мережі"""
        if self.net:
            info('*** Зупинка сервісів безпеки\n')
            self.ids.cmd('pkill snort')
            self.vpn.cmd('pkill openvpn')

            info('*** Зупиняємо мережу\n')
            self.net.stop()

    def get_firewall(self):
        """Отримання хоста firewall"""
        return self.firewall

    def get_ids(self):
        """Отримання хоста IDS"""
        return self.ids

    def get_vpn(self):
        """Отримання хоста VPN"""
        return self.vpn

    def get_client(self):
        """Отримання клієнтського хоста"""
        return self.client

    def get_server(self):
        """Отримання серверного хоста"""
        return self.server


if __name__ == '__main__':
    setLogLevel('info')
    topology = SecurityTopology()
    try:
        topology.start()
    finally:
        topology.stop()