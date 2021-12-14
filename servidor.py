#!/usr/bin/env python3.8

import socket
import ssl
import os
import sys
import threading
import pyshark
from colorama import init, Fore
from tqdm import tqdm
from time import sleep
import colorama
import argparse
import textwrap
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import traceback


def analizar_pcap(interactive, path):
    if interactive:
        ruta_fichero = str(input("Indica la ruta del fichero pcap: "))
    else:
        ruta_fichero = path
    print("")
    print("Filtrando archivo pcap...")
    pcap_filtrado = pyshark.FileCapture(ruta_fichero,
                                        display_filter='(tcp.dstport == 443 and tls.handshake.extensions_server_name) or (tcp.dstport == 443 and http.host)')
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


def analisis_en_tiempo_real(interactive, interface, packets):
    if interactive:
        interfaz = input(Fore.GREEN + "Introduce la interfaz por la que quieres capturar tráfico: ")
        paquetes = int(input(Fore.GREEN + "Introduce la cantidad de packetes que quieres capturar y comprobar: "))
    else:
        interfaz = interface
        paquetes = packets
    print("")
    print(Fore.BLUE + "Configurando interfaz y configurando los filtros...")
    captura = pyshark.LiveCapture(interface=(interfaz),
                                  display_filter='(tcp.dstport == 443 and tls.handshake.extensions_server_name) or (tcp.dstport == 443 and http.host)')
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
                f.write(
                    "[" + time + "]" + " " + ip_src + "[" + mac_src + "]" + " --> " + ip_dst + " Reason: " + server_name + " != " + http_host + "\n")
                f.close()
            else:
                print("")
                pass
                # print("Trafico normal")
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
            f.write(
                "[" + time + "]" + " " + ip_src + "[" + mac_src + "]" + " --> " + ip_dst + " Reason: " + server_name + " != " + http_host + "\n")
            f.close()
        else:
            print("")
            pass
            # print("Trafico normal")
    print("")
    input(Fore.BLUE + "Presiona cualquier boton para ir al menu principal.")
    if interactive:
        os.system("clear")
    print("")


def socket_escribir(lhost, lport):
    try:
        HOST = lhost  # Standard loopback interface address (localhost)
        PORT = lport  # Port to listen on (non-privileged ports are > 1023)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='/home/servidor/Escritorio/public.pem', keyfile='/home/servidor/Escritorio/key.key')

        bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bindsocket.bind((lhost, lport))
        bindsocket.listen()

        # Creamos/abrimos el fichero que va a almacenar los pre masters.
        try:
            f = open("/tmp/.ssl-key.log", "x")
            f = open("/tmp/.ssl-key.log", "wb")
        except:
            f = open("/tmp/.ssl-key.log", "wb")

        newsocket, fromaddr = bindsocket.accept()
        connstream = context.wrap_socket(newsocket, server_side=True)

        print(Fore.CYAN + 'Connected by: ', fromaddr)
        while True:
            try:
                data = connstream.recv(1024)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
                while data:
                    if not data:
                        break
                    data = connstream.recv(1024)
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                break
            except:
                connstream.close()
        connstream.close()
        f.close()
    except Exception:
        print("\n")
        print(Fore.RED + "[ERROR] No se ha podido iniciar el socket. Revisa que ningún cliente está activo.")
        traceback.print_exc()
        try:
            sys.exit(1)
        except:
            os._exit(1)


def main():
    # Inizializo el parser de argumentos
    parser = argparse.ArgumentParser(description="Herramienta diseñada para detectar enmascaramiento de trafico.")

    # Añado los argumentos.
    parser.add_argument('--LHOST', '-LHOST', type=str, help="The IP that is listening on the server.")
    parser.add_argument("--LPORT", "-LPORT", type=int, help="The port that is listening on the server.")
    parser.add_argument("--interface", "-i", type=str, help="The interface where are you going to listen in.")
    parser.add_argument("--packets", "-packets", type=int, help="The number of packets you want to analyze.")
    parser.add_argument("--path", "-path", type=str, help="The path to the pcap file.")
    parser.add_argument("--mode", "-m", type=int, help=textwrap.dedent('''\
                                                                                1 - Analyze pcap file.
                                                                                2 - Real time analysis.'''))
    parser.add_argument("--interactive", action="store_true", help="Initializate the tool in interactive mode.")
    arguments = parser.parse_args()

    # Controlo que no se inicialize el script sin argumentos.
    if (len(sys.argv) == 1):
        print(Fore.RED + "[ERROR] See help. View of help: python3 server.py -h")
        sys.exit(-1)

    # Inicio el hilo que se va a encargar de escuchar y escribir en el fichero.
    print(Fore.MAGENTA + "Iniciando Socket")

    # Creo variables esenciales.
    if not arguments.interactive:
        INTERACTIVE = False
        LHOST = arguments.LHOST
        LPORT = arguments.LPORT
        INTERFACE = arguments.interface
        PACKETS = arguments.packets
        PATH = arguments.path
        MODE = arguments.mode
    else:
        INTERACTIVE = True
        LHOST = str(input(Fore.GREEN + "Introduce la IP del servidor: "))
        LPORT = int(input(Fore.GREEN + "Introduce el puerto a la escucha: "))
        PATH = None
        INTERFACE = None
        PACKETS = None

    socket_writer = threading.Thread(target=socket_escribir, args=(LHOST, LPORT))
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

    if INTERACTIVE:
        opcion = ""
        while (True):
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
                analizar_pcap(INTERACTIVE, PATH)
            elif (opcion == '2'):
                analisis_en_tiempo_real(INTERACTIVE, INTERFACE, PACKETS)
    else:
        if (MODE == 1):
            analizar_pcap(INTERACTIVE, PATH)
            try:
                sys.exit(0)
            except SystemExit:
                os._exit(0)
        elif (MODE == 2):
            if (PACKETS == None) or (INTERFACE == None):
                print("Interface and packets are mandatory in cli mode.")
                os._exit(-1)
            analisis_en_tiempo_real(INTERACTIVE, INTERFACE, PACKETS)
            try:
                sys.exit(0)
            except SystemExit:
                os._exit(0)


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