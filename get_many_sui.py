from accounts import SuiWallet

#sui = SuiWallet.load_wallet('sui_wallets/4971318655_wallet.txt')
sui = SuiWallet('hybrid settle very brush east wing prevent utility balance square wire enrich')
sui.get_new_account_from_wallet()
# sui.save_wallet()

print(sui.accounts[0].get_private_hex())

for i in range(100000):
    sui.accounts[0].get_faucet()
