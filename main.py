from password import *
import argparse

if __name__ == "__main__":
    # execute only if run as a script
    parser = argparse.ArgumentParser()

    parser.add_argument("--password", help="length of the generated password", type=int)
    parser.add_argument("--purpose", help="purpose of the password generation", type=str)
    parser.add_argument("--file", help="file where password will be saved", type=str)
    parser.add_argument("--token", help="handle the token, deletion request => true or pass", type=str)
    parser.add_argument("--check",
                        help="check if the password you seek is correct compare to the hashed version => true or pass, type=str")
    args = parser.parse_args()
    if args.password:
        psswd = password_generation(args.password)
        hashed = crypt(save_crypt_key("salt.txt"), str(args.file), psswd, str(args.purpose))
        check(psswd, hashed)
    if args.token == "true":
        display_token("salt.txt")
    if args.check == "true":
        if args.purpose:
            if args.file:
                compare_hash(str(args.file), str(args.purpose))
            else:
                print("You need at least a purpose(--purpose) and a filename(--file) to decrypt a password")
        else:
            print("You need at least a purpose and a filename to decrypt a password")
    if args.check == "false":
        pass
    else:
        print("ERROR: {} is an invalid parameter for arg --check".format(args.check))
