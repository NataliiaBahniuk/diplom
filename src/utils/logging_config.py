import logging
import os
from datetime import datetime


def setup_logging(name, log_dir='logs'):
    """Налаштування логування"""
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Створюємо форматтер для логів
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Налаштовуємо файловий handler
    log_file = os.path.join(
        log_dir,
        f'{name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    )
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)

    # Налаштовуємо консольний handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # Налаштовуємо логер
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger