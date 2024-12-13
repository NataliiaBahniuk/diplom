# Використовуємо Ubuntu як базовий образ
FROM ubuntu:22.04

# Уникаємо інтерактивних запитів під час встановлення
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Встановлюємо необхідні пакети
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    openvswitch-switch \
    net-tools \
    iputils-ping \
    iproute2 \
    iptables \
    tcpdump \
    tshark \
    wireshark \
    nmap \
    hping3 \
    snort \
    openvpn \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Налаштовуємо дозволи для захоплення пакетів
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap

# Встановлюємо Mininet
RUN git clone https://github.com/mininet/mininet.git && \
    cd mininet && \
    git checkout -b 2.3.0 2.3.0 && \
    PYTHON=python3 ./util/install.sh -nfv && \
    cd .. && \
    rm -rf mininet

# Створюємо необхідні директорії
RUN mkdir -p /app/configs/firewall \
    /app/configs/ids \
    /app/configs/vpn \
    /var/log/snort \
    /var/log/openvpn

# Копіюємо конфігураційні файли
COPY ../configs/firewall/rules.json /app/configs/firewall/
COPY ../configs/ids/snort.conf /app/configs/ids/
COPY ../configs/vpn/openvpn.conf /app/configs/vpn/

# Копіюємо код проекту
COPY ../src/ /app/src/
COPY ../tests/ /app/tests/
COPY requirements.txt /app/

# Встановлюємо Python залежності
RUN pip3 install -r /app/requirements.txt

# Встановлюємо робочу директорію
WORKDIR /app

# Команда для запуску
CMD ["python3", "src/lab_runner.py"]