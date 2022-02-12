#!/bin/bash

sleep 4
echo "Trafico normal"
systemd-resolve --flush-caches
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName bitdefender.com -HostHeader bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 3
echo "Trafico ilicito"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName medium.com -HostHeader medium.com -serverName www.bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 1
echo "Trafico normal"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName bitdefender.com -HostHeader bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 1
echo "Trafico ilicito"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName medium.com -HostHeader medium.com -serverName www.bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 5
echo "Trafico normal"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName bitdefender.com -HostHeader bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 1
echo "Trafico normal"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName bitdefender.com -HostHeader bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 1
echo "Trafico ilicito"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName medium.com -HostHeader medium.com -serverName www.bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 2
echo "Trafico normal"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName bitdefender.com -HostHeader bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 1
echo "Trafico ilicito"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName medium.com -HostHeader medium.com -serverName www.bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 1
echo "Trafico normal"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName bitdefender.com -HostHeader bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 1
echo "Trafico ilicito"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName medium.com -HostHeader medium.com -serverName www.bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 4
echo "Trafico normal"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName bitdefender.com -HostHeader bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 1
echo "Trafico ilicito"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName medium.com -HostHeader medium.com -serverName www.bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 3
echo "Trafico normal"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName bitdefender.com -HostHeader bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 1
echo "Trafico normal"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName bitdefender.com -HostHeader bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 1
echo "Trafico ilicito"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName medium.com -HostHeader medium.com -serverName www.bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
sleep 1
echo "Trafico normal"
/home/cliente1/Escritorio/Noctilucent/client/build/noctilucent-client-linux -TLSHost www.bitdefender.com -esni -ESNIServerName bitdefender.com -HostHeader bitdefender.com > /dev/null 2>&1
systemd-resolve --flush-caches
echo""
echo "///////////////////////////////////////////"
echo "Trafico normal: 10"
echo "Trafico enmascarado (Domain Hiding): 7"
echo "//////////////////////////////////////////"
