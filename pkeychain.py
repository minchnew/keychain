#!/usr/bin/python

import os
import re
import sys
import random
import struct
import argparse
import hashlib
import getpass
from Crypto.Cipher import AES

parser = argparse.ArgumentParser(description="Put all your passwords into one \
                                 encrypted file. Search your passwords or add \
                                 new account info. It's kind of a lightweight \
                                 Keychain Access.")
parser.add_argument("file", help="File name of either plaintext or ciphertext")
# Optional Arguments: Basic mode
basic_mode = parser.add_mutually_exclusive_group()
basic_mode.add_argument("-e", "--encrypt", help="To encrypt a file", action=
                        "store_true") 
basic_mode.add_argument("-d", "--decrypt", help="To decrypt a file", action=
                        "store_true") 
# Optional Arguments: Search
group_search = parser.add_argument_group("Search", "Search your passwords")
group_search.add_argument("-s", "--search", help="Search by account description,\
                          e.g. Facebook, Yahoo!")
# Optional Arguments: Append
group_append = parser.add_argument_group("Append", "Add a new account")
group_append.add_argument("--append", help="Append an account info to the file",
                          action="store_true", default=False)
group_append.add_argument("-a", "--account", help="Account description")
group_append.add_argument("-u", "--user", help="Account username")
group_append.add_argument("-p", "--password", help="Account password")
args = parser.parse_args()

def prompt_for_password():
    '''
    A wrapper for getpass()
    '''
    pprompt = lambda:(getpass.getpass("Password:"), getpass.getpass("Retype Password:")) 
    first_pass, second_pass = pprompt()
    while first_pass != second_pass:
        print "Passwords do not match. Try again"
        first_pass, second_pass = pprompt()
    return first_pass

def encrypt(password, inputfile):
    """ Encrypts a file using AES (CBC mode) with the
        given password. Return a byte stream.
        password:
            The encryption password - Use AES-256. Use SHA-256
            to generate a 32-byte key from the password.
        inputfile:
            Name of the input file
    """
    ciphertext = ''
    chunksize = 4096
    if len(password) != 32:
        key = hashlib.sha256(password).digest()
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(inputfile)

    with open(inputfile, 'rb') as infile:
        ciphertext += struct.pack('<I', filesize) + iv

        while True:
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                # Padding
                chunk += ' ' * (16 - len(chunk) % 16)
            ciphertext += encryptor.encrypt(chunk)

    return ciphertext

def encrypt_stream(password, istream):
    """
    Almost like encrypt but it takes a stream as input.
    """
    ciphertext = ''
    chunksize = 4096
    if len(password) != 32:
        key = hashlib.sha256(password).digest()
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    size = len(istream)

    ciphertext += struct.pack('<I', size) + iv

    i = 0
    while True:
        chunk = istream[i:i+chunksize]
        if len(chunk) == 0:
            break
        elif len(chunk) % 16 != 0:
            # Padding
            chunk += ' ' * (16 - len(chunk) % 16)

        ciphertext += encryptor.encrypt(chunk)
        i += chunksize

    return ciphertext

def decrypt(password, inputfile):
    """
    Decrypts a file using AES (CBC mode) with the
    given password. Parameters are similar to encrypt.
    """
    plaintext = ''
    chunksize = 4096
    if len(password) != 32:
        key = hashlib.sha256(password).digest()
    with open(inputfile, 'rb') as infile:
        original_size = struct.unpack('<I', infile.read(struct.calcsize('I')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        while True:
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            plaintext += decryptor.decrypt(chunk)
    if plaintext[:4] != 'GEEK':
        print "Password Incorrect!"
        sys.exit(1)
    else:
        # strip padding
        return plaintext.strip(' ')

def main():
    # Encryption or decryption
    if args.encrypt:
        password = prompt_for_password()
        plaintext_fn = args.file
        ciphertext = encrypt(password, plaintext_fn)
        ciphertext_fn = plaintext_fn + '.enc'
        open(ciphertext_fn, 'wb').write(ciphertext)
    elif args.decrypt:
        password = getpass.getpass("Password:")
        ciphertext_fn = args.file
        plaintext = decrypt(password, ciphertext_fn)
        plaintext_fn = os.path.splitext(ciphertext_fn)[0]
        open(plaintext_fn, 'wb').write(plaintext)

    if args.search:
        password = getpass.getpass("Password:")
        ciphertext_fn = args.file
        plaintext_fn = os.path.splitext(ciphertext_fn)[0]
        plaintext = decrypt(password, ciphertext_fn)
        for entry in [line for line in plaintext.splitlines() if re.search(args.search, line)]:
            print entry,

    if args.append:
        password = getpass.getpass("Password:")
        ciphertext_fn = args.file
        plaintext_fn = os.path.splitext(ciphertext_fn)[0]
        plaintext = decrypt(password, ciphertext_fn)
        plaintext += '\t'.join((args.account, args.user, args.password)) + '\n'
        ciphertext = encrypt_stream(password, plaintext)
        with open(ciphertext_fn, 'wb') as outfile:
            outfile.write(ciphertext)

if __name__ == '__main__':
    main()
