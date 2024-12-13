import json
import subprocess
from mininet.log import info
import iptc


class Firewall:
    def __init__(self, node):
        """
        Ініціалізація файрвола на вказаному вузлі
        :param node: Mininet хост для налаштування файрвола
        """
        self.node = node
        self.rules = []

    def load_rules_from_file(self, rules_file):
        """
        Завантаження правил з JSON файлу
        :param rules_file: шлях до файлу з правилами
        """
        try:
            with open(rules_file, 'r') as f:
                self.rules = json.load(f)
            info(f'*** Loaded {len(self.rules)} firewall rules\n')
            return True
        except Exception as e:
            info(f'*** Error loading firewall rules: {e}\n')
            return False

    def apply_rules(self):
        """Застосування правил файрвола"""
        try:
            # Очищення існуючих правил
            self.node.cmd('iptables -F')
            self.node.cmd('iptables -X')

            # Встановлення політики за замовчуванням
            self.node.cmd('iptables -P INPUT DROP')
            self.node.cmd('iptables -P FORWARD DROP')

            # Дозволяємо локальний трафік
            self.node.cmd('iptables -A INPUT -i lo -j ACCEPT')

            # Дозволяємо встановлені з'єднання
            self.node.cmd('iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT')

            # Застосовуємо правила з конфігурації
            for rule in self.rules:
                command = self._build_iptables_command(rule)
                result = self.node.cmd(command)
                if result:
                    info(f'*** Error applying rule: {result}\n')

            info('*** Firewall rules applied successfully\n')
            return True
        except Exception as e:
            info(f'*** Error applying firewall rules: {e}\n')
            return False

    def _build_iptables_command(self, rule):
        """
        Побудова команди iptables з правила
        :param rule: словник з параметрами правила
        :return: командний рядок iptables
        """
        command = 'iptables'

        # Додаємо ланцюг
        if 'chain' in rule:
            command += f' -{rule["chain"]}'

        # Додаємо протокол
        if 'protocol' in rule:
            command += f' -p {rule["protocol"]}'

        # Додаємо source IP
        if 'source' in rule:
            command += f' -s {rule["source"]}'

        # Додаємо destination IP
        if 'destination' in rule:
            command += f' -d {rule["destination"]}'

        # Додаємо порт
        if 'port' in rule:
            if rule.get('protocol') in ['tcp', 'udp']:
                command += f' --dport {rule["port"]}'

        # Додаємо дію
        command += f' -j {rule.get("action", "DROP")}'

        return command

    def add_rule(self, rule_dict):
        """
        Додавання нового правила
        :param rule_dict: словник з параметрами правила
        """
        command = self._build_iptables_command(rule_dict)
        result = self.node.cmd(command)

        if not result:
            self.rules.append(rule_dict)
            return True
        return False

    def remove_rule(self, rule_dict):
        """
        Видалення правила
        :param rule_dict: словник з параметрами правила
        """
        command = self._build_iptables_command(rule_dict).replace('-A', '-D')
        result = self.node.cmd(command)

        if not result:
            self.rules.remove(rule_dict)
            return True
        return False

    def show_rules(self):
        """Показ поточних правил"""
        return self.node.cmd('iptables -L -n -v')

    def enable_nat(self, internal_interface, external_interface):
        """
        Налаштування NAT
        :param internal_interface: внутрішній інтерфейс
        :param external_interface: зовнішній інтерфейс
        """
        commands = [
            'sysctl -w net.ipv4.ip_forward=1',
            f'iptables -t nat -A POSTROUTING -o {external_interface} -j MASQUERADE',
            f'iptables -A FORWARD -i {internal_interface} -o {external_interface} -j ACCEPT',
            f'iptables -A FORWARD -i {external_interface} -o {internal_interface} -m state --state ESTABLISHED,RELATED -j ACCEPT'
        ]

        for cmd in commands:
            result = self.node.cmd(cmd)
            if result:
                info(f'*** Error configuring NAT: {result}\n')
                return False

        info('*** NAT configured successfully\n')
        return True

    def save_rules(self, filename):
        """
        Збереження поточних правил у файл
        :param filename: шлях до файлу для збереження
        """
        try:
            with open(filename, 'w') as f:
                json.dump(self.rules, f, indent=4)
            return True
        except Exception as e:
            info(f'*** Error saving firewall rules: {e}\n')
            return False

    def setup_port_forwarding(self, external_port, internal_ip, internal_port, protocol='tcp'):
        """
        Налаштування перенаправлення портів
        :param external_port: зовнішній порт
        :param internal_ip: внутрішня IP-адреса
        :param internal_port: внутрішній порт
        :param protocol: протокол (tcp/udp)
        """
        command = f'iptables -t nat -A PREROUTING -p {protocol} --dport {external_port} -j DNAT --to {internal_ip}:{internal_port}'
        result = self.node.cmd(command)

        if not result:
            info(f'*** Port forwarding configured: {external_port} -> {internal_ip}:{internal_port}\n')
            return True
        else:
            info(f'*** Error configuring port forwarding: {result}\n')
            return False