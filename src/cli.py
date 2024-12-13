import click
from mininet.log import setLogLevel, info
from topologies import SecurityTopology, AttackTopology, SecurityLabTopology
from security import Firewall, IDS, VPNManager
from attacks import DDoSAttack, MITMAttack, PortScanner
import os
import json


@click.group()
def cli():
    """Інтерфейс командного рядка для управління лабораторією мережевої безпеки"""
    setLogLevel('info')


@cli.group()
def topology():
    """Управління мережевими топологіями"""
    pass


@topology.command('security')
def start_security_topology():
    """Запуск базової топології безпеки"""
    topo = SecurityTopology()
    try:
        topo.start()
    finally:
        topo.stop()


@topology.command('attack')
@click.option('--attackers', default=1, help='Кількість атакуючих вузлів')
def start_attack_topology(attackers):
    """Запуск топології для тестування атак"""
    topo = AttackTopology()
    try:
        topo.build(n_attackers=attackers)
        topo.start()
    finally:
        topo.stop()


@topology.command('lab')
def start_lab_topology():
    """Запуск повної лабораторної топології"""
    topo = SecurityLabTopology()
    try:
        topo.start()
    finally:
        topo.stop()


@cli.group()
def attack():
    """Управління атаками"""
    pass


@attack.command('ddos')
@click.option('--target', required=True, help='IP-адреса цілі')
@click.option('--type', type=click.Choice(['tcp', 'udp', 'http']), default='tcp')
@click.option('--duration', default=60, help='Тривалість атаки в секундах')
def start_ddos(target, type, duration):
    """Запуск DDoS атаки"""
    topo = AttackTopology()
    net = topo.build()
    attacker = topo.get_attackers()[0]

    ddos = DDoSAttack(target)
    try:
        ddos.start_attack(attack_type=type)
        click.echo(f"DDoS атака запущена на {target}")
        time.sleep(duration)
    finally:
        ddos.stop_attack()
        net.stop()


@attack.command('mitm')
@click.option('--victim', required=True, help='IP-адреса жертви')
@click.option('--gateway', required=True, help='IP-адреса шлюзу')
def start_mitm(victim, gateway):
    """Запуск MITM атаки"""
    topo = AttackTopology()
    net = topo.build()
    attacker = topo.get_attackers()[0]

    mitm = MITMAttack(attacker, victim, gateway)
    try:
        mitm.start_attack()
        click.echo(f"MITM атака запущена")
        CLI(net)
    finally:
        mitm.stop_attack()
        net.stop()


@cli.group()
def security():
    """Управління безпекою"""
    pass


@security.command('firewall')
@click.option('--rules', type=click.Path(exists=True), help='Шлях до файлу з правилами')
def configure_firewall(rules):
    """Налаштування файрвола"""
    topo = SecurityLabTopology()
    net = topo.build()
    firewall_node = topo.get_firewall()

    fw = Firewall(firewall_node)
    try:
        if rules:
            fw.load_rules_from_file(rules)
        fw.apply_rules()
        click.echo("Файрвол налаштовано")
        CLI(net)
    finally:
        net.stop()


@security.command('ids')
def start_ids():
    """Запуск системи виявлення вторгнень"""
    topo = SecurityLabTopology()
    net = topo.build()
    ids_node = topo.get_ids()

    ids = IDS(ids_node)
    try:
        ids.configure('/app/configs/ids/snort.conf')
        ids.start_monitoring('ids-eth0')
        click.echo("IDS запущено")
        CLI(net)
    finally:
        ids.stop_monitoring()
        net.stop()


if __name__ == '__main__':
    cli()