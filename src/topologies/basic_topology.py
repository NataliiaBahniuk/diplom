from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

class BasicTopology:
    def __init__(self):
        self.net = None
        self.client1 = None
        self.client2 = None
        self.server = None

    def build(self):
        """Створення базової топології"""
        self.net = Mininet(
            controller=Controller,
            switch=OVSKernelSwitch,
            link=TCLink
        )

        info('*** Додаємо контролер\n')
        self.net.addController('c0')

        info('*** Додаємо комутатори\n')
        s1 = self.net.addSwitch('s1')
        s2 = self.net.addSwitch('s2')

        info('*** Додаємо хости\n')
        self.client1 = self.net.addHost(
            'client1',
            ip='10.0.1.10/24',
            defaultRoute='via 10.0.1.1'
        )
        self.client2 = self.net.addHost(
            'client2',
            ip='10.0.1.11/24',
            defaultRoute='via 10.0.1.1'
        )
        self.server = self.net.addHost(
            'server',
            ip='10.0.1.100/24',
            defaultRoute='via 10.0.1.1'
        )

        info('*** Створюємо з\'єднання\n')
        # З'єднання клієнтів з першим комутатором
        self.net.addLink(
            self.client1,
            s1,
            bw=10,
            delay='2ms',
            loss=0,
            max_queue_size=1000,
            use_htb=True
        )
        self.net.addLink(
            self.client2,
            s1,
            bw=10,
            delay='2ms',
            loss=0,
            max_queue_size=1000,
            use_htb=True
        )

        # З'єднання сервера з другим комутатором
        self.net.addLink(
            self.server,
            s2,
            bw=100,
            delay='1ms',
            loss=0,
            max_queue_size=1000,
            use_htb=True
        )

        # З'єднання комутаторів
        self.net.addLink(
            s1,
            s2,
            bw=100,
            delay='1ms',
            loss=0,
            max_queue_size=1000,
            use_htb=True
        )

        return self.net

    def configure(self):
        """Налаштування мережі"""
        # Налаштування маршрутизації
        for host in self.net.hosts:
            host.cmd('sysctl -w net.ipv4.ip_forward=1')

        # Налаштування правил для трафіку
        self.client1.cmd('tc qdisc add dev client1-eth0 root handle 1: htb default 10')
        self.client2.cmd('tc qdisc add dev client2-eth0 root handle 1: htb default 10')
        self.server.cmd('tc qdisc add dev server-eth0 root handle 1: htb default 10')

    def start(self):
        """Запуск мережі"""
        if self.net is None:
            self.build()

        info('*** Запускаємо мережу\n')
        self.net.start()

        info('*** Налаштовуємо мережу\n')
        self.configure()

        info('*** Перевіряємо з\'єднання\n')
        self.net.pingAll()

        info('*** Запускаємо CLI\n')
        CLI(self.net)

    def stop(self):
        """Зупинка мережі"""
        if self.net:
            info('*** Зупиняємо мережу\n')
            self.net.stop()

    def get_host(self, name):
        """Отримання хоста за іменем"""
        return self.net.get(name)

    def get_hosts(self):
        """Отримання всіх хостів"""
        return self.net.hosts

    def get_switches(self):
        """Отримання всіх комутаторів"""
        return self.net.switches

if __name__ == '__main__':
    setLogLevel('info')
    topology = BasicTopology()
    try:
        topology.start()
    finally:
        topology.stop()