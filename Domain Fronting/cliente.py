#!/usr/bin/env python3

import os
import sys
import socket
import ssl
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import time
from colorama import init, Fore
import argparse

# Funcion que sirve para leer el fichero que se escribe continuamente como pueden ser ficheros de logs.
# https://stackoverflow.com/questions/5419888/reading-from-a-frequently-updated-file
def follow(thefile):
    thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def main():
    #Limpio la terminal.
    os.system("clear")

    # Inizializo el parser de argumentos
    parser = argparse.ArgumentParser(description="Client of the tool designed to detect Domain Fronting.")

    # Añado los argumentos.
    parser.add_argument('--LHOST', '-LHOST', type=str, help="The IP that is listening on the server.")
    parser.add_argument("--LPORT", "-LPORT", type=int, help="The port that is listening on the server.")
    parser.add_argument("--interactive", action="store_true", help="Initializate the tool in interactive mode.")
    arguments = parser.parse_args()

    if (len(sys.argv) == 1):
        print(Fore.RED + "[ERROR] See help for a correct use of the tool. View of help: python3 server.py -h")
        sys.exit(-1)

    print("")
    print(Fore.BLUE + "/////////////////////////////////////////")
    print(Fore.BLUE + "Welcome to the client of Domain Fronting Detector.")
    print(Fore.BLUE + "/////////////////////////////////////////")
    print("")

    if (arguments.interactive):
        HOST = str(input(Fore.GREEN + "Enter the IP of the server: ")) # The server's hostname or IP address
        PORT = int(input("Enter the server port: ")) # The port used by the server
    else:
        HOST = arguments.LHOST
        PORT = arguments.LPORT

    file_exists = os.path.exists("/tmp/key-file.log")
    try:
        filesize = os.path.getsize("/tmp/key-file.log")
    except:
        filesize = 0

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('/home/kali/Desktop/public.pem')

    conn = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname="proxy.com")
    conn.connect((HOST, PORT))
    cert = conn.getpeercert()

    while file_exists != True or filesize == 0:
        file_exists = os.path.exists("/tmp/key-file.log")
        try:
            filesize = os.path.getsize("/tmp/key-file.log")
        except:
            filesize = 0

    f = open("/tmp/key-file.log", "rb")
    filelines = follow(f)
    for line in filelines:
        # print(line)
        conn.sendall(line)
    conn.close()
    print("The entire file has been sent.")

if __name__ == '__main__':
    try:
        init(autoreset=True)
        main()
    except KeyboardInterrupt:
        print("")
        print(Fore.YELLOW + "/////////////////////////")
        print(Fore.YELLOW + 'Finalizing process...')
        print(Fore.YELLOW + "/////////////////////////")
        print("")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)