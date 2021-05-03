import string
import random
import bcrypt
import re
import os.path
from os import path


def password_generation(l):
    """
    return password converted in bytes
    :param l: password length
    :return: byte object
    """
    # try:
    letters = string.ascii_letters
    numbers = string.digits
    punctuation = string.punctuation

    want_digits = bool(
        input("Want digits ? (Enter anything or leave empty if not): "))
    want_letters = bool(
        input("Want letters ? (Enter anything or leave empty if not): "))
    want_puncts = bool(
        input("Want punctuation ? (Enter anything or leave empty if not): "))
    if not want_digits:
        numbers = ""
    if not want_letters:
        letters = ""
    if not want_puncts:
        punctuation = ""
    ascii_caracters = f'{letters}{numbers}{punctuation}'
    assert ascii_caracters != ""
    ascii_caracters = list(ascii_caracters)
    random.shuffle(ascii_caracters)
    random_password = random.choices(ascii_caracters, weights=None, k=l)
    random_password = ''.join(random_password)
    print(random_password.encode())
    return random_password.encode()
    # except Exception:
    #     print(" Oops something went wrong!")


def save_crypt_key(filename):
    """
    save salt to txt file need to be destroyed after memorisation
    :param filename:
    :return: byte object
    """
    if not path.exists(filename):
        open(filename, 'w').close()
    else:
        with open(filename, "r+") as file:
            if len(file.read(1)) > 0:
                key = input("Enter the key: ")
                return key.encode()
            salt = bcrypt.gensalt()
            file.write(str(salt))
            return salt


def crypt(crypt_key, filename2, passwd, purpose):
    """
    crypt the generated password
    :param crypt_key:
    :param filename2:
    :param passwd:
    :param purpose:
    :return: byte object
    """
    hashed = bcrypt.hashpw(passwd, crypt_key)
    with open(filename2) as file:
        if not purpose in file.read():
            with open(filename2, "a") as file2:
                print("hashed: " + hashed.decode())
                file2.write(purpose + ': ' + str(hashed) + '\n')
                return hashed
    if purpose in file.read():
        print("FAILURE you cannot have two password for indentical purpose!!!")
        exit()


def check(passwd, hashed_password):
    """
    check if the operation was a success
    :param passwd:
    :param hashed_password:
    :return:
    """
    if bcrypt.checkpw(passwd, hashed_password):
        print("SUCCESS, this is your crypted password:" + passwd.decode())
    else:
        print("FAILURE, the password remains hashed " + hashed_password.decode())


def display_token(filename1):
    """
    Display the token and erase the file by security procedure
    :param filename1:
    :return:
    """
    with open(filename1, "r+") as file:
        crypt_key = file.readline()
        print("THE TOKEN: " + crypt_key)
        erase = bool(
            input("Do you want to erase the file? Enter anything or pass for NO: "))
        if erase:
            file.truncate(0)
        return


def compare_hash(filename2, pattern):
    with open(filename2, "r") as file:
        for l in file:
            if pattern in l:
                hashed = l[len(pattern) + 4:-1]
                hashed = hashed.encode()
                #print("hashed => => =>"+str(hashed))
                passw = input(
                    "Entry the password corresponding to the website or application in str:")
                passw=passw.encode()
                if bcrypt.hashpw(passw, hashed):
                    print("Correct Password!")
                    return True
                else:
                    print("Incorrect Password!")
                    return False
