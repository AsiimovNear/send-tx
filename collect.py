import requests
from web3 import Web3
import json

bsc = "https://bsc-dataseed.binance.org/"
web3 = Web3(Web3.HTTPProvider(bsc))
answer = True

while answer:
    contract_address = web3.toChecksumAddress(input('Enter contract address: ')).lower()
    API_ENDPOINT = "https://api.bscscan.com/api?module=contract&action=getabi&address=" + str(contract_address)
    r = requests.get(url=API_ENDPOINT)
    response = r.json()
    abi = json.loads(response["result"])
    contract = web3.eth.contract(address=web3.toChecksumAddress(contract_address), abi=abi)
    if input(f'Do you want to disperse {contract.functions.symbol().call()}?(y/N)').lower() == 'y':
        answer = False
    else:
        continue


def take_info():
    privates = {}
    binance_addresses = {}

    with open('addresses.txt', 'r') as file:
        for line in file.readlines():
            address_info = line.split(':')
            privates[address_info[0]] = address_info[1]
            binance_addresses[address_info[0]] = address_info[2].replace("\n", "")

    return privates, binance_addresses


def send_tx(from_address: str, private_key: str, to_address: str):
    from_address = web3.toChecksumAddress(from_address)
    to_address = web3.toChecksumAddress(to_address)
    amount = contract.functions.balanceOf(from_address).call()
    nonce = web3.eth.getTransactionCount(from_address)

    tx = {
        'gas': 100000,
        'gasPrice': web3.toWei('10', 'gwei'),
        'nonce': nonce
    }

    token_tx = contract.functions.transfer(to_address, amount).buildTransaction(tx)
    sign_txn = web3.eth.account.signTransaction(token_tx, private_key=private_key)
    txn_hash = web3.eth.sendRawTransaction(sign_txn.rawTransaction)
    web3.eth.wait_for_transaction_receipt(txn_hash)
    hash = str(sign_txn).split("'")
    hash = hash[hash.index('), hash=HexBytes(') + 1]
    print(f'{from_address}, {to_address}: {hash}')
    return hash


def to_txt(hash_data):
    with open("Hashes.txt", "w") as file:
        for hash in hash_data:
            file.write(f"{hash}\n")


def main():
    hash_data = []
    privates, bin_addresses = take_info()
    for address, key in privates.items():
        hash_data.append(send_tx(from_address=address, private_key=key, to_address=bin_addresses.get(address)))
    to_txt(hash_data)


if __name__ == '__main__':
    main()
