import pytest
from mininet.net import Mininet
from src.topologies import SecurityTopology, AttackTopology, SecurityLabTopology


@pytest.fixture
def security_topo():
    topo = SecurityTopology()
    net = topo.build()
    yield topo
    if net:
        net.stop()


@pytest.fixture
def attack_topo():
    topo = AttackTopology()
    net = topo.build()
    yield topo
    if net:
        net.stop()


@pytest.fixture
def security_lab_topo():
    topo = SecurityLabTopology()
    net = topo.build()
    yield topo
    if net:
        net.stop()


def test_security_topology_creation(security_topo):
    """Тест створення базової топології безпеки"""
    assert security_topo.net is not None
    assert len(security_topo.net.hosts) > 0
    assert len(security_topo.net.switches) > 0


def test_attack_topology_creation(attack_topo):
    """Тест створення топології для атак"""
    assert attack_topo.net is not None
    assert attack_topo.get_attacker() is not None
    assert attack_topo.get_victim() is not None
    assert attack_topo.get_gateway() is not None


def test_security_lab_topology_creation(security_lab_topo):
    """Тест створення лабораторної топології"""
    assert security_lab_topo.net is not None
    assert security_lab_topo.get_firewall() is not None
    assert security_lab_topo.get_ids() is not None
    assert security_lab_topo.get_vpn_server() is not None


def test_connectivity(security_topo):
    """Тест зв'язності в мережі"""
    net = security_topo.net
    h1 = net.get('h1')
    h2 = net.get('h2')

    # Перевіряємо ping між хостами
    result = h1.cmd(f'ping -c 1 {h2.IP()}')
    assert '1 received' in result


def test_security_components_setup(security_lab_topo):
    """Тест налаштування компонентів безпеки"""
    # Перевіряємо firewall
    firewall = security_lab_topo.get_firewall()
    assert 'iptables' in firewall.cmd('which iptables')

    # Перевіряємо IDS
    ids = security_lab_topo.get_ids()
    assert 'snort' in ids.cmd('which snort')

    # Перевіряємо VPN
    vpn = security_lab_topo.get_vpn_server()
    assert 'openvpn' in vpn.cmd('which openvpn')