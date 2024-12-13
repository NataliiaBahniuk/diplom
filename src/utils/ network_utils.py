import os
import subprocess
from mininet.util import quietRun
from mininet.log import info, error


def check_host_connectivity(host1, host2, count=1):
    """
    Перевірка з'єднання між хостами за допомогою ping
    """
    result = host1.cmd(f'ping -c {count} {host2.IP()}')
    return '0% packet loss' in result


def get_interface_info(host, interface):
    """
    Отримання інформації про мережевий інтерфейс
    """
    return host.cmd(f'ifconfig {interface}')


def capture_traffic(host, interface, duration=10, output_file=None):
    """
    Захоплення мережевого трафіку за допомогою tcpdump
    """
    if output_file is None:
        output_file = f'/tmp/capture_{host.name}_{interface}.pcap'

    cmd = f'tcpdump -i {interface} -w {output_file} &'
    host.cmd(cmd)

    # Чекаємо вказаний час
    host.cmd(f'sleep {duration}')

    # Зупиняємо tcpdump
    host.cmd('pkill tcpdump')
    return output_file


def setup_nat(host):
    """
    Налаштування NAT на хості
    """
    host.cmd('sysctl -w net.ipv4.ip_forward=1')
    host.cmd('iptables -t nat -A POSTROUTING -o {}-eth0 -j MASQUERADE'.format(host.name))


def setup_traffic_control(interface, delay=None, loss=None, bandwidth=None):
    """
    Налаштування параметрів мережі (затримка, втрати пакетів, пропускна здатність)
    """
    cmd = f'tc qdisc add dev {interface} root netem'
    if delay:
        cmd += f' delay {delay}ms'
    if loss:
        cmd += f' loss {loss}%'
    if bandwidth:
        cmd += f' rate {bandwidth}mbit'
    return quietRun(cmd)


def get_bandwidth(host1, host2, duration=5):
    """
    Вимірювання пропускної здатності між хостами за допомогою iperf
    """
    # Запускаємо iperf сервер на host2
    host2.cmd('iperf -s &')
    # Чекаємо секунду для запуску сервера
    host1.cmd('sleep 1')

    # Запускаємо клієнт на host1
    result = host1.cmd(f'iperf -c {host2.IP()} -t {duration}')

    # Зупиняємо сервер
    host2.cmd('pkill -9 iperf')

    return result


def configure_ovs_switch(switch, protocols='OpenFlow13'):
    """
    Налаштування OpenVSwitch
    """
    switch.cmd(f'ovs-vsctl set bridge {switch} protocols={protocols}')


def install_flow_rule(switch, rule):
    """
    Встановлення правила OpenFlow
    """
    switch.cmd(f'ovs-ofctl add-flow {switch} {rule}')