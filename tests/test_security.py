import pytest
from src.security import Firewall, IDS, VPNManager
from src.topologies import SecurityLabTopology


@pytest.fixture
def security_environment():
    topo = SecurityLabTopology()
    net = topo.build()
    yield topo
    if net:
        net.stop()


def test_firewall_setup(security_environment):
    """Тест налаштування файрвола"""
    firewall_node = security_environment.get_firewall()
    fw = Firewall(firewall_node)

    # Тестуємо додавання правил
    rule = {
        'chain': 'INPUT',
        'protocol': 'tcp',
        'port': 80,
        'action': 'ACCEPT'
    }
    assert fw.add_rule(rule)

    # Перевіряємо, що правило додано
    rules = fw.show_rules()
    assert 'tcp dpt:80' in rules


def test_ids_configuration(security_environment):
    """Тест налаштування IDS"""
    ids_node = security_environment.get_ids()
    ids = IDS(ids_node)

    # Тестуємо конфігурацію
    assert ids.configure('/app/configs/ids/snort.conf')

    # Запускаємо моніторинг
    assert ids.start_monitoring('ids-eth0')

    # Перевіряємо, що процес запущено
    assert 'snort' in ids_node.cmd('ps aux | grep snort')

    # Зупиняємо моніторинг
    ids.stop_monitoring()


def test_vpn_setup(security_environment):
    """Тест налаштування VPN"""
    vpn_node = security_environment.get_vpn_server()
    vpn = VPNManager(vpn_node)

    # Тестуємо налаштування
    assert vpn.setup('/app/configs/vpn/openvpn.conf')

    # Генеруємо сертифікати
    assert vpn.generate_certificates()

    # Створюємо клієнтську конфігурацію
    client_config = vpn.generate_client_config('test_client')
    assert client_config is not None
    assert 'test_client' in client_config


def test_firewall_nat(security_environment):
    """Тест NAT налаштувань файрвола"""
    firewall_node = security_environment.get_firewall()
    fw = Firewall(firewall_node)

    # Налаштовуємо NAT
    assert fw.enable_nat('firewall-eth0', 'firewall-eth1')

    # Перевіряємо правила NAT
    nat_rules
    # Перевіряємо правила NAT
    nat_rules = firewall_node.cmd('iptables -t nat -L')
    assert 'MASQUERADE' in nat_rules


def test_ids_alerts(security_environment):
    """Тест алертів IDS"""
    ids_node = security_environment.get_ids()
    ids = IDS(ids_node)

    # Налаштовуємо і запускаємо IDS
    ids.configure('/app/configs/ids/snort.conf')
    ids.start_monitoring('ids-eth0')

    # Додаємо тестове правило
    test_rule = 'alert tcp any any -> any 80 (msg:"Test HTTP traffic"; sid:1000001; rev:1;)'
    assert ids.add_rule(test_rule)

    # Генеруємо тестовий трафік
    client = security_environment.get_client()
    client.cmd('wget http://10.0.0.10')

    # Перевіряємо наявність алертів
    alerts = ids.get_alerts()
    assert len(alerts) > 0

    ids.stop_monitoring()


def test_vpn_client_management(security_environment):
    """Тест управління клієнтами VPN"""
    vpn_node = security_environment.get_vpn_server()
    vpn = VPNManager(vpn_node)

    # Налаштовуємо VPN
    vpn.setup('/app/configs/vpn/openvpn.conf')
    vpn.generate_certificates()

    # Створюємо клієнта
    client_config = vpn.generate_client_config('test_client')
    assert client_config is not None

    # Відкликаємо сертифікат клієнта
    assert vpn.revoke_client('test_client')

    # Перевіряємо список підключених клієнтів
    clients = vpn.get_connected_clients()
    assert isinstance(clients, list)


def test_security_integration(security_environment):
    """Тест інтеграції компонентів безпеки"""
    # Налаштовуємо всі компоненти
    firewall = Firewall(security_environment.get_firewall())
    ids = IDS(security_environment.get_ids())
    vpn = VPNManager(security_environment.get_vpn_server())

    # Налаштовуємо правила файрвола
    firewall.add_rule({
        'chain': 'FORWARD',
        'protocol': 'tcp',
        'port': 1194,
        'action': 'ACCEPT'
    })

    # Запускаємо IDS
    ids.start_monitoring('ids-eth0')

    # Запускаємо VPN сервер
    vpn.start_server()

    # Перевіряємо статус всіх сервісів
    assert 'ACCEPT' in firewall.show_rules()
    assert ids.is_monitoring
    assert vpn.is_running

    # Зупиняємо сервіси
    ids.stop_monitoring()
    vpn.stop_server()