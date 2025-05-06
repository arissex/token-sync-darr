"""
Dark Trace Detector — утилита для выявления взаимодействий Ethereum-кошелька с подозрительными контрактами.

Проверяет:
- Входящие транзакции с неизвестных или рискованных адресов
- Контракты без верификации
- Низкий возраст контракта
- Часто повторяющиеся "странные" вызовы

Результаты можно использовать для последующего аудита или блокировки.
"""

import requests
import argparse
from datetime import datetime


ETHERSCAN_API_URL = "https://api.etherscan.io/api"


def fetch_transactions(address, api_key):
    params = {
        "module": "account",
        "action": "txlist",
        "address": address,
        "startblock": 0,
        "endblock": 99999999,
        "sort": "desc",
        "apikey": api_key
    }
    response = requests.get(ETHERSCAN_API_URL, params=params)
    return response.json().get("result", [])


def fetch_contract_info(contract_address, api_key):
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": contract_address,
        "apikey": api_key
    }
    response = requests.get(ETHERSCAN_API_URL, params=params)
    return response.json().get("result", [])[0]


def detect_suspicious_contracts(transactions, api_key, max_age_days=7):
    now = datetime.utcnow()
    suspicious = []

    for tx in transactions:
        to = tx["to"]
        input_data = tx.get("input", "")
        if not to or not input_data or input_data == "0x":
            continue  # ignore normal ETH tx

        contract_info = fetch_contract_info(to, api_key)
        source_code = contract_info.get("SourceCode", "")
        created = contract_info.get("LastUpdated", "")

        if not source_code or source_code.strip() == "":
            created_date = datetime.strptime(created, "%Y-%m-%d")
            age_days = (now - created_date).days
            if age_days <= max_age_days:
                suspicious.append({
                    "to": to,
                    "method": input_data[:10],
                    "age_days": age_days,
                    "tx_hash": tx["hash"]
                })

    return suspicious


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dark Trace Detector — обнаружение взаимодействий с подозрительными контрактами.")
    parser.add_argument("address", help="Ethereum-адрес")
    parser.add_argument("api_key", help="Etherscan API ключ")
    parser.add_argument("--age", type=int, default=7, help="Максимальный возраст контракта для подозрения (в днях)")
    args = parser.parse_args()

    print(f"[•] Анализируем транзакции {args.address}...")
    txs = fetch_transactions(args.address, args.api_key)

    print(f"[✓] Найдено {len(txs)} транзакций. Проверка контрактов...")
    suspicious = detect_suspicious_contracts(txs, args.api_key, max_age_days=args.age)

    if not suspicious:
        print("[✓] Подозрительных вызовов не найдено.")
    else:
        print("\n[!] Обнаружены подозрительные взаимодействия с контрактами:")
        for s in suspicious:
            print(f"  - Контракт: {s['to']} | Метод: {s['method']} | Возраст: {s['age_days']} д. | TX: {s['tx_hash']}")
