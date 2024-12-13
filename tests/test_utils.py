import pytest
from src.utils.network_utils import *
from src.utils.monitoring import NetworkMonitor
from src.utils.traffic_analyzer import TrafficAnalyzer
import time


def test_network_monitor():
    """Тест моніторингу мережі"""
    monitor = NetworkMonitor()

    # Тест збору метрик
    monitor.start_monitoring()
    monitor.collect_metrics()

    assert len(monitor.data['timestamp']) > 0
    assert len(monitor.data['cpu_percent']) > 0
    assert len(monitor.data['memory_percent']) > 0

    # Тест моніторингу з інтервалом
    monitor.monitor(duration=2, interval=1)
    assert len(monitor.data['timestamp']) >= 2


def test_traffic_analyzer():
    """Тест аналізатора трафіку"""
    analyzer = TrafficAnalyzer()

    # Тест захоплення трафіку
    capture_file = analyzer.capture_live('eth0', duration=1)
    assert capture_file is not None

    # Тест аналізу захопленого трафіку
    stats = analyzer.analyze_capture(capture_file)
    assert isinstance(stats, dict)
    assert 'packet_count' in stats


def test_network_utils():
    """Тест мережевих утиліт"""
    # Тест отримання інформації про інтерфейс
    interface_info = get_interface_info('eth0')
    assert interface_info is not None

    # Тест налаштування traffic control
    result = setup_traffic_control('eth0', delay='100ms', loss=1)
    assert result is not None