#!/usr/bin/env python3.8

import socket
import os
import sys
import threading
import pyshark
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
    interfaz = input("Introduce la interfaz por la que quieres capturar tráfico: ")
    print("")
    print("Configurando interfaz y configurando los filtros...")
    captura = pyshark.LiveCapture(interface=(interfaz), display_filter='(tcp.dstport == 443 and tls.handshake.extensions_server_name) or (tcp.dstport == 443 and http.host)')
    print("")

    print("Iniciando analisis:")
    print("")
    server_name = ''
    http_host = ''
    time = ''
    ip_src = ''
    ip_dst = ''
    mac_src = ''
    validador = False
    for packet in captura.sniff_continuously(packet_count=34):
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

def socket_escribir():
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
            print('Connected by: ', addr)
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

def main():
    # Inicio el hilo que se va a encargar de escuchar y escribir en el fichero.
    print("Iniciando Socket")
    print(".....")
    print(".....")
    socket_writer = threading.Thread(target=socket_escribir)
    socket_writer.start()
    print("Socket iniciado")

    opcion = ""
    while(True):
        print("")
        print("/////////////////////////////////////////")
        print("Bienvenido a Domain Fronting detector.")
        print("/////////////////////////////////////////")
        print("")
        print("1) Analizar un archivo pcap en busca de enmascaramiento de tráfico")
        print("2) Analisis en tiempo real.")
        print("3) Salir.")
        print("")
        opcion = str(input("Introduce la opcion elegida: "))
        print("")

        if (opcion == '3'):
            exit()
        elif (opcion == '1'):
            analizar_pcap()
        elif (opcion == '2'):
            analisis_en_tiempo_real()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("")
        print("/////////////////////////")
        print('Terminando proceso...')
        print("/////////////////////////")
        print("")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)