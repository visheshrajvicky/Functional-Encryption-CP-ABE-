from charm.toolbox.pairinggroup import PairingGroup, GT
from cp_abe import CP_ABE


def main():
    pairing_group = PairingGroup('MNT224')
    
    cpabe = CP_ABE(pairing_group, 2)

    # run the set up
    (public_key, master_secrete_key) = cpabe.setup()
    #print(master_secrete_key)

    # generate a key
    attribute_lst = ['ONE', 'TWO', 'THREE']
    key = cpabe.keygen(public_key, master_secrete_key, attribute_lst)
    print("key ", key,"\n\n")

    # choose a random message
    message = pairing_group.random(GT)
    print(message,"\n\n")
   
    # generate a ciphertext
    policy = '((ONE and THREE) and (TWO OR FOUR))'
    cipher_text = cpabe.encrypt(public_key, message, policy)
    print(cipher_text,"\n\n")

    # decryption
    recieved_message = cpabe.decrypt(public_key, cipher_text, key)
    print(recieved_message,"\n\n")
    if debug:
        if recieved_message == message:
            print ("Successful decryption.")
        else:
            print ("Decryption failed.")


if __name__ == "__main__":
    debug = True
    main()
