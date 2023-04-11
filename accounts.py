import base64
import bip_utils
import hashlib
import nacl
import binascii
import os
from cryto_pass import cryto_pass, decryto_pass
import random, json
import uuid
from sui_cli import send, get_objects, switch, all_failed_set


from curl_cffi import requests

class SignatureScheme:
    ED25519 = 'ED25519'
    Secp256k1 = 'Secp256k1'

url = 'https://fullnode.testnet.sui.io'
class Account:
    def __init__(self, public_key, private_key) -> None:
      self.public_key = public_key
      self.private_key = private_key
      self.address = self.get_address()

    def get_address(self) -> str:
        # return "0x" + hashlib.sha3_256(self.bip32_der_ctx.PublicKey().RawCompressed().ToBytes()).digest().hex()[:40]
        return "0x" + hashlib.blake2b(self.public_key, digest_size=32).digest().hex()

    def get_private_hex(self):
        return binascii.hexlify(self.private_key).decode()

    def get_private_base64(self):
        return base64.b64encode(binascii.unhexlify('00'+self.get_private_hex())).decode()

    def sign_data(self, data: bytes) -> bytes:
        # Todo: support secp256k1 key and signature
        return nacl.signing.SigningKey(self.private_key).sign(data)[:64]
    
    def get_public_key_as_b64_string(self) -> str:
        return base64.b64encode(self.public_key[1:]).decode()

    def get_example_nft(self):
        pass

    def get_faucet(self, rpc='https://faucet.testnet.sui.io/gas'):
        headers = {
            'content-type': 'application/json',
        }
        data = '''{
                "FixedAmountRequest": {
                    "recipient": "%s"
                }
            }''' % self.get_address()
        n = 0
        print(self.get_address(), "get faucet:")
        print("____________________________________________")
        for i in range(2, 15):
            if n >= 1:
                break
            s = requests.Session()
            response = s.post(
                f'https://faucet.testnet.sui.io/gas', headers=headers, data=data, impersonate="chrome110")
            try:
                # print(response.text)
                text = json.loads(response.text)
                n+=1
                print(n, 'success', text)
            except json.JSONDecodeError as e:
                print("fail")


            for i in range(1):
                response = s.post(
                    f'https://faucet.testnet.sui.io/gas', cookies=dict(response.cookies), headers=headers, data=data, impersonate="chrome110")
                try:
                    # print(response.text)
                    text = json.loads(response.text)
                    n += 1
                    print(n, 'success', text)
                except json.JSONDecodeError as e:
                    print("fail")
        print("____________________________________________")
        

class SuiWallet:
    def __init__(self, mnemonic: str, derivation_path="m/44'/784'/0'/0'/0'"):
        self.mnemonic = mnemonic
        self.derivation_path = derivation_path
        self.accounts = []
        self.cur_index= 0
        self.get_new_account_from_wallet()
    
    def increase_index(self):
        self.cur_index += 1
        self.derivation_path = "m/44'/784'/" + str(self.cur_index) + "'/0'/0'"

    def get_new_account_from_wallet(self):
        bip39_seed = bip_utils.Bip39SeedGenerator(
            self.mnemonic).Generate()

        bip32_ctx = bip_utils.Bip32Slip10Ed25519.FromSeed(bip39_seed)
        bip32_der_ctx = bip32_ctx.DerivePath(self.derivation_path)

        private_key: bytes = bip32_der_ctx.PrivateKey().Raw().ToBytes()
        public_key: bytes = bip32_der_ctx.PublicKey().RawCompressed().ToBytes()
        acc = Account(public_key, private_key)
        self.accounts.append(acc)
        self.increase_index()
        return acc
    
    # def get_account_from_derivation(self, derivation_path):
    #     bip39_seed = bip_utils.Bip39SeedGenerator(
    #         self.mnemonic).Generate()

    #     bip32_ctx = bip_utils.Bip32Slip10Ed25519.FromSeed(bip39_seed)
    #     bip32_der_ctx = bip32_ctx.DerivePath(derivation_path)

    #     private_key: bytes = bip32_der_ctx.PrivateKey().Raw().ToBytes()
    #     public_key: bytes = bip32_der_ctx.PublicKey().RawCompressed().ToBytes()
    #     acc = Account(public_key, private_key)
    #     self.accounts.append(acc)
    #     return acc

    def save_wallet(self):
        os.system('mkdir -p sui_wallets')
        random_name = str(random.randint(0, 10000000000)) + '_wallet.txt'
        with open('sui_wallets/' + random_name, 'w') as f:
            obj = {
                'mnemonic': self.mnemonic,
                'index': self.cur_index
            }
            f.write(cryto_pass(json.dumps(obj)))

    @staticmethod
    def load_wallet(path):
        sui = None
        with open(path, 'r') as f:
            obj = json.loads(decryto_pass(f.read()))
            mnemonic = obj['mnemonic']
            cur_index = obj['index']
            sui = SuiWallet(mnemonic)
            for i in range(cur_index-1):
                sui.get_new_account_from_wallet()
        return sui
            


    @staticmethod
    def create_random_wallet():
        return SuiWallet(
            mnemonic=bip_utils.Bip39MnemonicGenerator().FromWordsNumber(bip_utils.Bip39WordsNum.WORDS_NUM_12).ToStr())
    

    # def get_address(self) -> str:
    #     # return "0x" + hashlib.sha3_256(self.bip32_der_ctx.PublicKey().RawCompressed().ToBytes()).digest().hex()[:40]
    #     return "0x" + hashlib.blake2b(self.public_key, digest_size=32).digest().hex()

    # def get_private_hex(self):
    #     return binascii.hexlify(self.private_key).decode()

    # def sign_data(self, data: bytes) -> bytes:
    #     # Todo: support secp256k1 key and signature
    #     return nacl.signing.SigningKey(self.private_key).sign(data)[:64]

    # def get_public_key_as_b64_string(self) -> str:
        # return base64.b64encode(self.public_key[1:]).decode()

def add_addresses_to_config(accounts):
    home = os.path.expanduser("~")
    sui_path = os.path.join(home, '.sui/sui_config/sui.keystore')
    with open(sui_path, 'r') as f:
        config = json.load(f)

    for acc in accounts:
        private_key = acc.get_private_base64()
        if private_key not in config:
            config.append(private_key)
            print(private_key)
    
    s = '[\n'
    for i, c in enumerate(config):
        if i == len(config) - 1:
            s += '    "' + c + '"\n'
        else:
            s += '    "' + c + '",\n'
    s += ']'
    with open(sui_path, 'w') as f:
        f.write(s)

def get_faucet_from_account(accounts):
    for acc in accounts:
        acc.get_faucet()
        # import ipdb;ipdb.set_trace()



def get_balance(address):
    params = [address, '0x2::sui::SUI']
    data = {
        'method': 'suix_getBalance',
        'jsonrpc': '2.0',
        'params': params,
        'id': str(uuid.uuid4())
    }

    response = requests.post(url, data=json.dumps(data), headers={'Content-Type': 'application/json'})
    print(response.text)
    if response.status_code == 200:
        return response.json()['result']
    else:
        return None

if __name__ == '__main__':

    # 第一次运行
    # sui = SuiWallet.create_random_wallet()
    # 一个助记词可以管理无数个账户
    # print(sui.mnemonic)
    # # 会让你输一个密码然后会保存下来，保存路径sui_wallets/xxxx_wallet.txt
    # sui.save_wallet()

    # 之后想增加钱包
    # sui = SuiWallet.load_wallet('sui_wallets/xxxx_wallet.txt')
    # for i in range(100):
    #     sui.get_new_account_from_wallet()
    #     # print(i)
    # accounts = sui.accounts
    # add_addresses_to_config(accounts)
    # sui.save_wallet()

    # 转账
    # sui = SuiWallet.load_wallet('sui_wallets/xxxx_wallet.txt')
    # accounts = sui.accounts
    # pairs = list(zip(accounts[0::2], accounts[1::2]))
    # random.shuffle(pairs)
    # for a,b in pairs:
    #     switch(a.address)
    #     # a.get_faucet()
    #     send(b.address, a)
    #     switch(b.address)
    #     # b.get_faucet()
    #     send(a.address, b)


#### 调试代码，运行上面的把下面的注释掉
    # sui = SuiWallet(
        # 'poem wish key moon library labor height celery enjoy before history torch')
    sui = SuiWallet.load_wallet('/Volumes/xwt2101239.asuscomm.com/important/sui_sdk/sui_wallets/4845042328_wallet.txt')
    # for i in range(1000):
    #     sui.get_new_account_from_wallet()
    #     # print(i)
    # sui.save_wallet()
    accounts = sui.accounts
    # import ipdb;ipdb.set_trace()
    # add_addresses_to_config(accounts)
    # get_faucet_from_account(accounts)
    pairs = list(zip(accounts[0::2], accounts[1::2]))
    random.shuffle(pairs)

    for a,b in pairs:
        switch(a.address)
        # a.get_faucet()
        send(b.address, a)
        switch(b.address)
        # b.get_faucet()
        send(a.address, b)

    # save all_failed_set
    print('all failed len', len(all_failed_set))
    with open('all_failed_set.txt', 'w') as f:
        f.write(json.dumps(list(all_failed_set)))
    # get_balance('0x2e97827c44282348c7ed7769407805c86212faec588d431ef94d6f9e5107abdd')
    # import ipdb;ipdb.set_trace()
