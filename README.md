# Reverse Engineering LockerGoga

Scripts and other resources from LockerGoga ransomware reverse engineering effort.

**decrypt_file.py** - a script capable of decrypting a file that was encrypted by a specific LockerGoga with a known public-private key pair (likely works with most other variants and can be modified)
**generate_binary.py** - accepts a minimum of a file to patch and file offset then generates a binary patched with a newly generated public key, with also accept two optional private key and public key file outputs