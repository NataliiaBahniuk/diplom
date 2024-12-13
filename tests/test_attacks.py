import pytest
from src.attacks import DDoSAttack, MITMAttack, PortScanner
from src.topologies import AttackTopology


@pytest.fixture
def attack_environment():
    topo = AttackTopology()
    net = topo.build()
    yield topo
    if net:
        net.stop()


def test_ddos_attack_creation(attack_environment):
    """Тест створення DDoS атаки"""
    victim = attack_environment.get_victim()
    attacker = attack_environment.get_attacker()

    ddos = DDoSAttack(victim)
    assert ddos is not None

    # Перевіряємо наявність необхідних методів
    assert hasattr(ddos, 'start_attack')
    assert hasattr(ddos, 'stop_attack')


def test_mitm_attack_setup(attack_environment):
    """Тест налаштування MITM атаки"""
    attacker = attack_environment.get_attacker()
    victim = attack_environment.get_victim()
    gateway = attack_environment.get_gateway()

    mitm = MITMAttack(attacker, victim, gateway)
    assert mitm is not None

    # Перевіряємо IP forwarding
    mitm.enable_ip_forward()
    result = attacker.cmd('cat /proc/sys/net/ipv4/ip_forward')
    assert '1' in result


def test_port_scanner(attack_environment):
    """Тест сканера портів"""
    victim = attack_environment.get_victim()
    scanner = PortScanner(victim)

    # Запускаємо тестовий веб-сервер на жертві
    victim.cmd('python3 -m http.server 80 &')

    # Скануємо порти
    results = scanner.start_scan(start_port=79, end_port=81)
    assert 80 in results

    # Зупиняємо сервер
    victim.cmd('pkill -f "python3 -m http.server"')


def test_attack_stopping(attack_environment):
    """Тест зупинки атак"""
    victim = attack_environment.get_victim()
    attacker = attack_environment.get_attacker()

    # DDoS
    ddos = DDoSAttack(victim)
    ddos.start_attack()
    assert ddos.stop_attack()

    # MITM
    mitm = MITMAttack(attacker, victim, attack_environment.get_gateway())
    mitm.start_attack()
    assert mitm.stop_attack()


def test_attack_monitoring(attack_environment):
    """Тест моніторингу атак"""
    victim = attack_environment.get_victim()

    # Запускаємо DDoS атаку
    ddos = DDoSAttack(victim)
    ddos.start_attack(num_threads=1)  # Мінімальна кількість потоків для тесту

    # Перевіряємо навантаження на мережу
    initial_stats = victim.cmd('netstat -i | grep eth0')
    ddos.stop_attack()
    final_stats = victim.cmd('netstat -i | grep eth0')

    assert initial_stats != final_stats