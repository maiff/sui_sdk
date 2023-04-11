import subprocess
import json
import random
import time
# output = subprocess.check_output("ls")
# print(output)

# def new_address(scheme='ed25519'):
    # return subprocess.check_output("sui address new --scheme " + scheme, shell=True).decode('utf-8').strip()
all_send_cnt = 0
all_failed_set = set()

def get_objects(n=5):
    output = None
    if n == 0:
        return []
    try:
        objects = []
        p = subprocess.Popen('sui client objects --json', stdout=subprocess.PIPE, shell=True)
        output, err = p.communicate()
        # output = subprocess.run(["sui", "client" ,"objects"], stdout=subprocess.PIPE)
        # output = output.stdout.decode('utf-8')
        # import ipdb;ipdb.set_trace()
        objs =  json.loads(output)
        for obj in objs:
            data = obj['data']
            content = data['content']
            coin_type = content['type']
            if coin_type == '0x2::coin::Coin<0x2::sui::SUI>':
                objects.append(data['objectId'])
        return objects
    except Exception as e:
        print('objects',e)
        print(output)
        return get_objects(n-1)

def send(address, account, n=5):
    global all_send_cnt
    if n == 0:
        all_failed_set.add(account.address)
        return None
    amounts = random.randint(1, 9)
    amounts *= 100000000
    gas_budget = random.randint(500000000, 1000000000)
    objects = get_objects()
    output = None
    try:
        input_coins = ' '.join(objects)

        p = subprocess.Popen(f'sui client pay_sui --amounts {amounts} --gas-budget {gas_budget} --recipients {address} --input-coins {input_coins} --json', stdout=subprocess.PIPE, shell=True)
        output, err = p.communicate()
        objs =  json.loads(output)
        all_send_cnt+=1
        print('send success', all_send_cnt , address, objs["digest"])
        return objs
    except Exception as e:
        print('send', e)
        print(output)
        output = output.decode()
        if 'does not exist' in output:
            print('object not save sleep 2 s')
            time.sleep(2)
        else:
            account.get_faucet()
        return send(address, account, n-1)

def switch(address):
    p = subprocess.Popen(f'sui client switch --address {address}', stdout=subprocess.PIPE, shell=True)
    output, err = p.communicate()
    print(output)
    return output

if __name__ == '__main__':
    print(send('0x8eaa9999f6670b3efcad7ac1687aa618ddcd4a7b3d9edd039b6492becb8be135'))