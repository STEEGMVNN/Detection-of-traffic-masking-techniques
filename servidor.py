#!/usr/bin/env python3.8

import socket
import os
import sys
import threading
import pyshark
from colorama import init, Fore
from tqdm import tqdm
from time import sleep
import colorama
#import argparse
import textwrap
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

def analizar_pcap():
    ruta_fichero = str(input("Indica la ruta del fichero pcap: "))
    print("")
    print("Filtrando archivo pcap...")
    pcap_filtrado = pyshark.FileCapture(ruta_fichero, display_filter='(tcp.dstport == 443 and tls.handshake.extensions_server_name) or (tcp.dstport == 443 and http.host)')
    print("")

    print("Iniciando analisis:")
    print("")
    print("")

    server_name = ''
    http_host = ''
    time = ''
    ip_src = ''
    ip_dst = ''
    mac_src = ''
    validador = False
    for packet in pcap_filtrado:
        if (validador == True):
            if (server_name != http_host):
                print("")
                print("///////////////////////////////////////////")
                print("ALERT!!!! DOMAIN FRONTING DETECTED!!!!")
                print("     -Time: " + time)
                print("     -MAC source: " + mac_src)
                print("     -IP source: " + ip_src)
                print("     -IP destination: " + ip_dst)
                print("     -Server Name: " + server_name)
                print("     -HTTP Host: " + http_host)
                print("////////////////////////////////////////////")
            else:
                print("")
                print("Trafico normal")
        try:
            server_name = str(packet.tls.handshake_extensions_server_name)
            validador = False
        except:
            pass

        try:
            http_host = str(packet.http.host)
            http_host = "www."+http_host
            time = str(packet.frame_info.time)
            ip_src = str(packet.ip.src)
            ip_dst = str(packet.ip.dst)
            mac_src = str(packet.eth.src)
            validador = True
        except:
            pass
    if (validador == True):
        if (server_name != http_host):
            print("")
            print("///////////////////////////////////////////")
            print("ALERT!!!! DOMAIN FRONTING DETECTED!!!!")
            print("     -Time: " + time)
            print("     -MAC source: " + mac_src)
            print("     -IP source: " + ip_src)
            print("     -IP destination: " + ip_dst)
            print("     -Server Name: " + server_name)
            print("     -HTTP Host: " + http_host)
            print("////////////////////////////////////////////")
        else:
            print("")
            print("Trafico normal")
    print("")
    input("Presiona cualquier boton para ir al menu principal.")
    print("")

def analisis_en_tiempo_real():
    interfaz = input(Fore.GREEN + "Introduce la interfaz por la que quieres capturar tráfico: ")
    paquetes = int(input(Fore.GREEN + "Introduce la cantidad de packetes que quieres capturar y comprobar: "))
    print("")
    print(Fore.BLUE + "Configurando interfaz y configurando los filtros...")
    captura = pyshark.LiveCapture(interface=(interfaz), display_filter='(tcp.dstport == 443 and tls.handshake.extensions_server_name) or (tcp.dstport == 443 and http.host)')
    print("")

    print(Fore.BLUE + "Iniciando analisis:")
    print("")
    server_name = ''
    http_host = ''
    time = ''
    ip_src = ''
    ip_dst = ''
    mac_src = ''
    validador = False
    for packet in captura.sniff_continuously(packet_count=paquetes):
        if (validador == True):
            if (server_name != http_host):
                print("")
                print(Fore.YELLOW + "///////////////////////////////////////////")
                print(Fore.YELLOW + "ALERT!!!! DOMAIN FRONTING DETECTED!!!!")
                print(Fore.YELLOW + "     -Time: " + time)
                print(Fore.YELLOW + "     -MAC source: " + mac_src)
                print(Fore.YELLOW + "     -IP source: " + ip_src)
                print(Fore.YELLOW + "     -IP destination: " + ip_dst)
                print(Fore.YELLOW + "     -Server Name: " + server_name)
                print(Fore.YELLOW + "     -HTTP Host: " + http_host)
                print(Fore.YELLOW + "////////////////////////////////////////////")
                f = open("/var/log/demasc/alerts.log", "a")
                f.write("[" + time + "]" + " " + ip_src + "[" + mac_src + "]" + " --> " + ip_dst + " Reason: " + server_name + " != " + http_host+"\n")
                f.close()
            else:
                print("")
                pass
                #print("Trafico normal")
        try:
            server_name = str(packet.tls.handshake_extensions_server_name)
            validador = False
        except:
            pass

        try:
            http_host = str(packet.http.host)
            http_host = "www." + http_host
            time = str(packet.frame_info.time)
            ip_src = str(packet.ip.src)
            ip_dst = str(packet.ip.dst)
            mac_src = str(packet.eth.src)
            validador = True
        except:
            pass
    if (validador == True):
        if (server_name != http_host):
            print("")
            print(Fore.YELLOW + "///////////////////////////////////////////")
            print(Fore.YELLOW + "ALERT!!!! DOMAIN FRONTING DETECTED!!!!")
            print(Fore.YELLOW + "     -Time: " + time)
            print(Fore.YELLOW + "     -MAC source: " + mac_src)
            print(Fore.YELLOW + "     -IP source: " + ip_src)
            print(Fore.YELLOW + "     -IP destination: " + ip_dst)
            print(Fore.YELLOW + "     -Server Name: " + server_name)
            print(Fore.YELLOW + "     -HTTP Host: " + http_host)
            print(Fore.YELLOW + "////////////////////////////////////////////")
            f = open("/var/log/demasc/alerts.log", "a")
            f.write("[" + time + "]" + " " + ip_src + "[" + mac_src + "]" + " --> " + ip_dst + " Reason: " + server_name + " != " + http_host+"\n")
            f.close()
        else:
            print("")
            pass
            #print("Trafico normal")
    print("")
    input(Fore.BLUE + "Presiona cualquier boton para ir al menu principal.")
    os.system("clear")
    print("")

def socket_escribir():
    try:
        default_length = 256
        # Generating private key (RsaKey object) of key length of 1024 bits
        private_key = RSA.generate(2048)
        # Generating the public key (RsaKey object) from the private key
        public_key = private_key.publickey()

        # Converting the RsaKey objects to string
        public_pem = public_key.export_key().decode()

        # Instantiating PKCS1_OAEP object with the private key for decryption
        decrypt = PKCS1_OAEP.new(key=private_key)

        HOST = '192.168.1.11'  # Standard loopback interface address (localhost)
        PORT = 4444  # Port to listen on (non-privileged ports are > 1023)

        # Creamos/abrimos el fichero que va a almacenar los pre masters.
        try:
            f = open("/tmp/.ssl-key.log", "x")
            f = open("/tmp/.ssl-key.log", "w")
        except:
            f = open("/tmp/.ssl-key.log", "w")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print(Fore.CYAN + 'Connected by: ', addr)
                conn.sendall(str.encode(public_pem))
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    length = len(data)
                    offset = 0
                    res = []

                    while length - offset > 0:
                        if length - offset > default_length:
                            res.append(decrypt.decrypt(data[offset: offset + default_length]))
                        else:
                            res.append(decrypt.decrypt(data[offset:]))
                        offset += default_length
                    decrypt_byte = b''.join(res)
                    decrypted = decrypt_byte.decode()
                    f.write(decrypted)
                    f.flush()
                    os.fsync(f.fileno())
            f.close()
            conn.close()
            print("Escrito el fichero")
    except:
        print("\n")
        print(Fore.RED + "[ERROR] No se ha podido iniciar el socket. Revisa que ningún cliente está activo.")
        try:
            sys.exit(1)
        except:
            os._exit(1)

def main():
    """# Inizializo el parser de argumentos
    parser = argparse.ArgumentParser(add_help=True, formatter_class=argparse.RawTextHelpFormatter)
    # Añado los argumentos
    parser.add_argument("<IP listening>", type=str, help="The IP that is listening on the server.")
    parser.add_argument("<PORT listening>", type=int, help="The port that is listening on the server.")
    parser.add_argument("<MODE>", type=str, help= textwrap.dedent('''\
                                                                        1 - Analyze pcap file.
                                                                        2 - Real time analysis.'''))
    # Parseo los argumentos.
    args = parser.parse_args(['<IP listening>', 'ip'])"""

    # Inicio el hilo que se va a encargar de escuchar y escribir en el fichero.
    print(Fore.MAGENTA + "Iniciando Socket")
    socket_writer = threading.Thread(target=socket_escribir)
    socket_writer.start()
    for i in tqdm(range(0, 100), colour="magenta", desc="Socket starting"):
        sleep(.1)
    print(Fore.MAGENTA + "Socket iniciado")

    # Compruebo si existe el fichero de logs de este programa. Si no existe lo creo.
    folder_exists = os.path.isdir('/var/log/demasc')
    if folder_exists:
        file_exists = os.path.exists('/var/log/demasc/alerts.log')

        if not file_exists:
            f = open("/var/log/demasc/alerts.log", "w")
            f.close()
    else:
        os.mkdir('/var/log/demasc')
        f = open("/var/log/demasc/alerts.log", "w")
        f.close()

    opcion = ""
    while(True):
        print("")
        print(Fore.BLUE + "/////////////////////////////////////////")
        print(Fore.BLUE + "Bienvenido a Domain Fronting detector.")
        print(Fore.BLUE + "/////////////////////////////////////////")
        print("")
        print(Fore.BLUE + "1) Analizar un archivo pcap en busca de enmascaramiento de tráfico")
        print(Fore.BLUE + "2) Analisis en tiempo real.")
        print(Fore.BLUE + "3) Salir.")
        print("")
        opcion = str(input(Fore.GREEN + "Introduce la opcion elegida: "))
        print("")

        if (opcion == '3'):
            raise KeyboardInterrupt
        elif (opcion == '1'):
            analizar_pcap()
        elif (opcion == '2'):
            analisis_en_tiempo_real()

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