# Network Security Laboratory

Лабораторний комплекс для дослідження захисту в комп'ютерних мережах на базі Mininet.

## Вимоги
- Docker
- Docker Compose

## Встановлення

```bash
# Клонуємо репозиторій
git clone https://github.com/yourusername/network-security-lab.git
cd network-security-lab

# Збираємо Docker образ
docker-compose build

# Запускаємо контейнер
docker-compose up -d
```

## Використання

1. Увійдіть в контейнер:
```bash
docker-compose exec network-lab bash
```

2. Запустіть базову топологію:
```bash
python3 src/topologies/basic_topology.py
```

## Структура проекту

- `src/` - вихідний код
  - `topologies/` - мережеві топології
  - `attacks/` - імплементації атак
  - `security/` - механізми захисту
  - `utils/` - утиліти
- `configs/` - конфігураційні файли
- `tests/` - тести
- `docker/` - файли для Docker

## Ліцензія
MIT