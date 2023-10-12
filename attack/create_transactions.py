from xrpl.wallet import Wallet


def main():
    genesis_seed = "snoPBrXtMeMyMHUVTgbuqAfg1SUTb"
    src_seed = "sEd7gsxCwikqZ9C81bjKMFNM9xoReYU"        # generated with keypairs.generate_seed()
    dest1_seed = "sEdSt227nt6yWUmMmVqFQNPiqns6Edg"       # generated with keypairs.generate_seed()
    dest2_seed = "sEdTWpq82NtG2aMwwX8A42pDFmLWs7q"       # generated with keypairs.generate_seed()
    
    src_wallet = Wallet.from_seed(seed=src_seed)
    dest1_wallet = Wallet.from_seed(seed=dest1_seed)
    dest2_wallet = Wallet.from_seed(seed=dest2_seed)

    # rippled works unexpected with " or '. Encoding transactions as one string, however, is enough for our purpose.
    base_tx = "{ \"Account\": \"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh\", \"Amount\": \"1000000000\", \"Destination\": \"$(src_address)\", \
               \"TransactionType\": \"Payment\", \"Fee\": \"10\" }".replace("$(src_address)", src_wallet.address)   # from genesis to src_address
    tx1 = "{ \"Account\": \"$(src_address)\", \"Amount\": \"1000000000\", \
           \"Destination\": \"$(dest_address)\", \"TransactionType\": \"Payment\", \
           \"Fee\": \"10\" }".replace("$(src_address)", src_wallet.address).replace("$(dest_address)", dest1_wallet.address)    # from src_address to dest1_address
    tx2 = "{ \"Account\": \"$(src_address)\", \"Amount\": \"1000000000\", \
           \"Destination\": \"$(dest_address)\", \"TransactionType\": \"Payment\", \
           \"Fee\": \"10\" }".replace("$(src_address)", src_wallet.address).replace("$(dest_address)", dest2_wallet.address)    # from src_address to dest2_address

    print(f"rippled submit {genesis_seed} '{base_tx}'")
    print(f"rippled submit {src_seed} '{tx1}'")
    print(f"rippled submit {src_seed} '{tx2}'")


if __name__=="__main__":
    main()
