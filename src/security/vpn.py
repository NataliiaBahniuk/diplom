import os
import subprocess
from mininet.log import info
import time
import signal


class VPNManager:
    def __init__(self, node):
        """
        Ініціалізація менеджера VPN
        :param node: Mininet хост для налаштування VPN
        """
        self.node = node
        self.vpn_process = None
        self.config_dir = '/etc/openvpn'
        self.is_running = False

    def setup(self, config_file):
        """
        Налаштування OpenVPN з конфігураційного файлу
        :param config_file: шлях до конфігураційного файлу
        """
        try:
            # Створюємо необхідні директорії
            self.node.cmd(f'mkdir -p {self.config_dir}')
            self.node.cmd(f'mkdir -p {self.config_dir}/ccd')

            # Копіюємо конфігураційний файл
            self.node.cmd(f'cp {config_file} {self.config_dir}/server.conf')

            info('*** VPN configuration copied successfully\n')
            return True
        except Exception as e:
            info(f'*** Error setting up VPN: {e}\n')
            return False

    def generate_certificates(self):
        """Генерація сертифікатів для VPN"""
        try:
            # Створюємо директорію для PKI
            self.node.cmd('mkdir -p /etc/openvpn/easy-rsa')
            self.node.cmd('cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/')

            # Ініціалізуємо PKI
            with self.node.popen('cd /etc/openvpn/easy-rsa && ./easyrsa init-pki',
                                 shell=True, stdout=subprocess.PIPE) as proc:
                output = proc.communicate()[0]

            # Генеруємо сертифікат CA
            with self.node.popen('cd /etc/openvpn/easy-rsa && ./easyrsa build-ca nopass',
                                 shell=True, stdout=subprocess.PIPE) as proc:
                output = proc.communicate()[0]

            # Генеруємо сертифікат сервера
            with self.node.popen('cd /etc/openvpn/easy-rsa && ./easyrsa build-server-full server nopass',
                                 shell=True, stdout=subprocess.PIPE) as proc:
                output = proc.communicate()[0]

            info('*** VPN certificates generated successfully\n')
            return True
        except
            info('*** VPN certificates generated successfully\n')
            return True
        except Exception as e:
            info(f'*** Error generating certificates: {e}\n')
            return False

        def start_server(self):
            """Запуск VPN сервера"""
            if self.is_running:
                info('*** VPN server is already running\n')
                return False

            try:
                # Запускаємо OpenVPN сервер
                command = f'openvpn --config {self.config_dir}/server.conf'
                self.vpn_process = self.node.popen(command.split(),
                                                   stdout=subprocess.PIPE,
                                                   stderr=subprocess.PIPE)

                # Чекаємо поки сервер запуститься
                time.sleep(2)

                if self.vpn_process.poll() is None:
                    self.is_running = True
                    info('*** VPN server started successfully\n')
                    return True
                else:
                    error = self.vpn_process.stderr.read()
                    info(f'*** Error starting VPN server: {error}\n')
                    return False

            except Exception as e:
                info(f'*** Error starting VPN server: {e}\n')
                return False

        def stop_server(self):
            """Зупинка VPN сервера"""
            if not self.is_running:
                return True

            try:
                if self.vpn_process:
                    self.vpn_process.send_signal(signal.SIGTERM)
                    self.vpn_process.wait(timeout=5)

                self.is_running = False
                info('*** VPN server stopped\n')
                return True
            except Exception as e:
                info(f'*** Error stopping VPN server: {e}\n')
                return False

        def generate_client_config(self, client_name):
            """
            Генерація конфігурації для клієнта
            :param client_name: ім'я клієнта
            :return: шлях до створеного конфігураційного файлу
            """
            try:
                # Генеруємо сертифікат клієнта
                self.node.cmd(f'cd /etc/openvpn/easy-rsa && ./easyrsa build-client-full {client_name} nopass')

                # Створюємо директорію для клієнтських конфігурацій
                client_dir = f'{self.config_dir}/clients/{client_name}'
                self.node.cmd(f'mkdir -p {client_dir}')

                # Копіюємо необхідні файли
                self.node.cmd(f'cp /etc/openvpn/easy-rsa/pki/ca.crt {client_dir}/')
                self.node.cmd(f'cp /etc/openvpn/easy-rsa/pki/issued/{client_name}.crt {client_dir}/')
                self.node.cmd(f'cp /etc/openvpn/easy-rsa/pki/private/{client_name}.key {client_dir}/')

                # Створюємо конфігураційний файл клієнта
                config_path = f'{client_dir}/{client_name}.ovpn'
                with open(config_path, 'w') as f:
                    f.write('''client
            dev tun
            proto udp
            remote SERVER_IP 1194
            resolv-retry infinite
            nobind
            persist-key
            persist-tun
            ca ca.crt
            cert CLIENT.crt
            key CLIENT.key
            remote-cert-tls server
            cipher AES-256-CBC
            verb 3'''.replace('SERVER_IP', self.node.IP())
                            .replace('CLIENT', client_name))

                info(f'*** Generated client configuration for {client_name}\n')
                return config_path
            except Exception as e:
                info(f'*** Error generating client configuration: {e}\n')
                return None

        def revoke_client(self, client_name):
            """
            Відкликання сертифіката клієнта
            :param client_name: ім'я клієнта
            """
            try:
                # Відкликаємо сертифікат
                self.node.cmd(f'cd /etc/openvpn/easy-rsa && ./easyrsa revoke {client_name}')

                # Оновлюємо CRL
                self.node.cmd('cd /etc/openvpn/easy-rsa && ./easyrsa gen-crl')

                # Копіюємо оновлений CRL
                self.node.cmd('cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/')

                info(f'*** Revoked certificate for {client_name}\n')
                return True
            except Exception as e:
                info(f'*** Error revoking certificate: {e}\n')
                return False

        def get_connected_clients(self):
            """Отримання списку підключених клієнтів"""
            try:
                status = self.node.cmd('cat /etc/openvpn/openvpn-status.log')
                clients = []

                # Парсимо лог-файл статусу
                in_client_list = False
                for line in status.splitlines():
                    if line.startswith('Common Name'):
                        in_client_list = True
                        continue
                    if in_client_list and line.strip():
                        if line.startswith('ROUTING TABLE'):
                            break
                        parts = line.split(',')
                        if len(parts) >= 3:
                            clients.append({
                                'name': parts[0],
                                'ip': parts[1],
                                'connected_since': parts[4]
                            })

                return clients
            except Exception as e:
                info(f'*** Error getting connected clients: {e}\n')
                return []