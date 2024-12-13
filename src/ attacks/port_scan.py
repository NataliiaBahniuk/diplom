import nmap
from mininet.log import info
import socket
import threading
import queue
import time


class PortScanner:
    def __init__(self, target_host):
        self.target_host = target_host
        self.target_ip = target_host.IP()
        self.scan_results = {}
        self.port_queue = queue.Queue()
        self.scan_running = False

    def simple_port_scan(self, port):
        """Простий скан одного порту"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((self.target_ip, port))
        sock.close()
        return result == 0

    def worker(self):
        """Робочий потік для сканування портів"""
        while self.scan_running:
            try:
                port = self.port_queue.get_nowait()
            except queue.Empty:
                break

            if self.simple_port_scan(port):
                service = self._get_service_name(port)
                self.scan_results[port] = service
                info(f'*** Found open port {port} ({service})\n')

            self.port_queue.task_done()

    def _get_service_name(self, port):
        """Отримання назви сервісу для порту"""
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"

    def start_scan(self, start_port=1, end_port=1024, num_threads=10):
        """Запуск сканування портів"""
        self.scan_running = True
        self.scan_results.clear()

        info(f'*** Starting port scan on {self.target_ip}\n')

        # Заповнюємо чергу портами
        for port in range(start_port, end_port + 1):
            self.port_queue.put(port)

        # Запускаємо потоки для сканування
        threads = []
        for _ in range(min(num_threads, end_port - start_port + 1)):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)

        # Чекаємо завершення сканування
        self.port_queue.join()
        self.scan_running = False

        for t in threads:
            t.join()

        info(f'*** Port scan completed. Found {len(self.scan_results)} open ports\n')
        return self.scan_results

    def nmap_scan(self, ports=None, arguments="-sS -sV"):
        """Розширене сканування за допомогою nmap"""
        nm = nmap.PortScanner()

        if ports:
            ports_str = ",".join(map(str, ports))
            arguments += f" -p {ports_str}"

        info(f'*** Starting Nmap scan on {self.target_ip}\n')
        nm.scan(self.target_ip, arguments=arguments)

        results = {}
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    results[port] = {
                        'state': service['state'],
                        'name': service['name'],
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                    }

        info(f'*** Nmap scan completed\n')
        return results

    def generate_report(self, filename):
        """Генерація звіту про сканування"""
        with open(filename, 'w') as f:
            f.write("Port Scan Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Target Host: {self.target_ip}\n")
            f.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("Open Ports:\n")
            f.write("-" * 50 + "\n")

            for port, service in sorted(self.scan_results.items()):
                f.write(f"Port {port}: {service}\n")

        info(f'*** Scan report saved to {filename}\n')
        return filename