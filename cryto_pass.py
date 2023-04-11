from cryptography.fernet import Fernet
import base64
import getpass

def deal_pass(key):
    key = key[:32]
    key = key.ljust(32, '0')
    encoded_string = base64.urlsafe_b64encode(
        key.encode('utf-8'))  # 编码并转换为字符串
    return encoded_string
  
def cryto_pass(plaintext='test', is_input=False):
    # 生成一个随机密钥
    key = getpass.getpass(prompt='请输入密码：')
    encoded_string = deal_pass(key)
    # import ipdb;ipdb.set_trace()
    # key = Fernet.generate_key()
    # import ipdb;ipdb.set_trace()
    # 创建一个Fernet对象，使用该密钥进行加密和解密
    cipher_suite = Fernet(encoded_string)

    # 用户输入需要加密的字符串，并进行加密
    if is_input:
        plaintext = input('请输入需要加密的字符串：')
    plaintext = plaintext.encode()
    ciphertext = cipher_suite.encrypt(plaintext).decode()
    print("加密后的字符串为：", ciphertext)
    return ciphertext

def decryto_pass(password):
    key = getpass.getpass(prompt='请输入密码：')
    encoded_string = deal_pass(key)

    cipher_suite = Fernet(encoded_string)
    decrypted_text = cipher_suite.decrypt(password)
    return decrypted_text.decode()


if __name__ == '__main__':
  print(decryto_pass(cryto_pass('test', True)))
