
# LockerGoga Patcher and File Decryptor
  
Scripts and other resources from LockerGoga ransomware reverse engineering effort: these tools are to be used for **analysis and training purposes only**.
  

 - **decrypt_goga.py** - a script capable of LockerGoga file decryption with files that were encrypted with a known RSA public/private key
   pair.
   - The decrypt_goga.py script works with a specific variant of LockerGoga but likely works with most other variants and can be modified. The most important part is the patching the LockerGoga sample with a known, good RSA public/private key pair; then when decrypting an encrypted file, this script will parse all of the footer information, such as the CRC32 (4 bytes), 'GOGA' magic (4 bytes), '1440' version (4 bytes), original file size (8 bytes), and then the RSA encrypted AES key (16 bytes), and AES IV/seed (16 bytes) which are used to encrypt the file data. The AES is implemented as AES-128 bit (CTR) where it encrypts the file data in 0x10000 byte chunks. The script parses this information and then uses it to decrypt the AES key and IV using the known RSA private key. 

- **patch_goga.py** - accepts a minimum of a file to patch and file offset then generates a binary patched with a newly generated public key, with also accept two optional private key and public key file outputs
	- The patch_goga.py script fulfills the need for a known public/private key pair patched sample. This script generates a new public and private key pair and accepts a file (ideally LockerGoga) and a file offset where the generated public key will be patched into. Both the public and private key are exported as files private_key.pem and public_key.pem (but can be changed by specifying with `--out_private` and `--out_public`.
