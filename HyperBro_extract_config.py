#!/usr/bin/env python3
import argparse
import string
import sys
import lznt1 # Big thanks to you0708, which implemented LZNT1 in Python :) -> https://github.com/you0708/lznt1

def utf_16_to_ascii(data):
    data_clean = "".join(filter(lambda x: x in set(string.printable), data)).replace("\x0b", "").replace("\x0c", "").replace("\t", "")
    return data_clean

def decrypt(data, key, verbose=False):
    # decryption with one-byte key. Adapt this function if "encryption" algorithm changes
    data_decrypted = bytes([((b + key) & 0xff) for b in data])

    # The following links should be found in the PE Loader / decrypted Stage 2
    if verbose:
        if b"KERNEL32" in data_decrypted or b"GlobalA" in data_decrypted or b"Sleep" in data_decrypted: 
            print("[*] Decryption successful")
        else: 
            print("[*] Decryption not successful")
    return data_decrypted

# Brute-force one-byte key
def find_key(data, verbose=False):
    for i in range(256):
        data_decrypted = decrypt(data, i)
        if b"KERNEL32" in data_decrypted or b"GlobalA" in data_decrypted or b"Sleep" in data_decrypted: 
            return i, data_decrypted
    return None, None

def extract_config(data_dec):
    global args
    # If you compress a PE file with lznt1 this is the resulting header. It seems to be unique enough to find the beginnging of the compressed PE file / Stage 3
    compressed_PE_signature = b"\xfc\xb9\x00MZ\x90"
    try:
        start_compressed_PE = data_dec.index(compressed_PE_signature)
    except:
        print("[!] Compressed PE signature could not be found. Are you sure that the decryption key is correct?")
        print("[!] You might need to change the signature used for finding the beginning of the compressed PE file / Stage 3")
        print("[!] Exiting")
        exit(1)

    compressed_PE = data_dec[start_compressed_PE:]
    decompressed_PE = lznt1.decompress(compressed_PE)

    if b"WinHttp" in decompressed_PE:
        print("[*] Decompression of PE successful")
    
    if args.output_file:
        with open(args.output_file, "wb") as f:
            f.write(decompressed_PE)

    if args.dump_strings:
        print("[*] Dump all strings from Stage 3")
        all_strings = utf_16_to_ascii(decompressed_PE.decode("UTF-16", errors="ignore"))
        print(all_strings)

    if args.parse_config:
        # Note that the addresses for the config parser are harc-coded
        # If the config parser does not work for your sample, you should use the -d option, which dumps all strings 
        config_encoded = decompressed_PE[0x13710:0x13850].decode("UTF-16", errors="ignore")
        config_decoded = []
        for c in config_encoded.split("\x00"):
            config_decoded.append(utf_16_to_ascii(c))
        legit_launcher = config_decoded[1]
        stage1 = config_decoded[2]
        stage2 = config_decoded[3]
        stage3 = config_decoded[3]
        malware_dir = config_decoded[4]
        domain = config_decoded[5]
        windows_service_presistence = config_decoded[9]
        c2_ip = config_decoded[12]

        user_agent = utf_16_to_ascii(decompressed_PE[0x00010d10:0x010e00].decode("UTF-16", errors="ignore"))
        request_information = utf_16_to_ascii(decompressed_PE[0x00010930:0x00010974].decode("UTF-16", errors="ignore"))
        ipc_pipe = utf_16_to_ascii(decompressed_PE[0x00010972:0x00010998].decode("UTF-16", errors="ignore"))

        print("[*] HyperBro extracted config: ")
        print("Legit launcher used for DLL-Side-Loading:  " + legit_launcher)
        print("Stage 1:                                   " + stage1)
        print("Stage 2:                                   " + stage2)
        print("Stage 3:                                   " + stage3)
        print("Malware Directory:                         " + malware_dir)
        print("Domain (changed at runtime):               " + domain)
        print("Windows Service used for persistence:      " + windows_service_presistence)
        print("Command and Control IP address:            " + c2_ip)
        print("User Agent:                                " + user_agent)
        print("HTTPS Request Information:                 " + request_information)
        print("Pipe name used for IPC:                    " + ipc_pipe)


def parse_args():
    global modules
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-i", "--input", action="store", dest="input_file", required=True, help="The input file for this script should be Stage 2 of HyperBro. In our case, this file was named thumb.dat")
    parser.add_argument("-p", "--parse_config", action="store_true", dest="parse_config", default=False, help="Tries to parse the configuration of the HyperBro Stage 3 malware automatically. Might not work for newer samples")
    parser.add_argument("-d", "--dump_strings", action="store_true", dest="dump_strings",  default=False, help="Dumps all strings from the HyperBro Stage 3 malware")
    parser.add_argument("-o", "--output", action="store", dest="output_file", help="Write the decrypted and decompressed Stage 3 to a file. Note that the decryption might not work for newer samples, which do not have a one-byte key")
    parser.add_argument("-k", "--decryption_key", action="store", dest="decryption_key", help="This decryption key (currently a single hex byte) is used to decrypt Stage 2. If non is provided, the script tries to brute-force a one-byte key, which was used in our case.")

    args_parsed = parser.parse_args(sys.argv[1:])
    return args_parsed

args = parse_args()

with open(args.input_file, "rb") as fp:
    thumb_dat = fp.read()

if args.decryption_key:
    key = int(args.decryption_key, 16)
    thumb_dat_decrypted = decrypt(thumb_dat, key, verbose=True)
else:
    key, thumb_dat_decrypted = find_key(thumb_dat, verbose=True)
    if key is None or thumb_dat_decrypted is None:
        print("[-] Could not find decryption key")
        exit(1)

print("[*] The key is: " + str(hex(key)))
extract_config(thumb_dat_decrypted)
