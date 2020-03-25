#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.PublicKey import RSA
from Crypto import Random
from shutil import copyfile


def gen_key_patch(file_patch, file_offset, private_key_file, public_key_file):
    print('Generating RSA key...')
    rsa_key = RSA.generate(1024, Random.new().read)  # generates key
    print('RSA key generated!')

    print('Exporting RSA private key...')
    prv_exported = rsa_key.exportKey()  # exports private key as format
    print('RSA private key exported!')

    print('Exporting RSA public key...')
    pub_exported = rsa_key.publickey().exportKey()  # public key exported
    print('RSA public key exported!')

    # PATCHING FILE WITH PUBLIC KEY
    print('Backing up file (%s)...' % file_patch)
    copyfile(file_patch, file_patch + '_backup')

    print('Patching provided file (%s) using offset...' % file_patch)
    patch_file = open(file_patch, 'r+b')  # open file to patch
    patch_file.seek(file_offset)  # move to public key
    parsed_public_key = pub_exported[27:-25]  # parse public key data
    patch_file.write(parsed_public_key)  # parses extra from PEM public key
    patch_file.close()  # close file
    print('File (%s) patched!' % file_patch)

    # PRIVATE KEY FILE
    print('Writing new private key to %s...' % private_key_file)
    priv_file = open(private_key_file, 'wb')  # opens new private key file
    priv_file.write(prv_exported)  # write private key data to file
    priv_file.close()  # close private file
    print('New private key written to %s!' % private_key_file)

    # PUBLIC KEY FILE
    print('Writing new public key to %s...' % public_key_file)
    pub_file = open(public_key_file, 'wb')  # opens new public key file
    pub_file.write(pub_exported)  # write public key data to file
    pub_file.close()  # close public file
    print('New public key written to %s!' % public_key_file)

if __name__ == '__main__':
    # global settings
    FILE_TO_PATCH = 'test/data/getafmald_7bcd69_copy.exe'
    FILE_PATCH_OFFSET = 0xFCE28

    PRIVATE_KEY_FILE = 'test/data/private_key.pem'
    PUBLIC_KEY_FILE = 'test/data/public_key.pem'

    gen_key_patch(FILE_TO_PATCH, FILE_PATCH_OFFSET, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)
    exit()