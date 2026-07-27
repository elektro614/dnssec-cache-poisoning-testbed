#!/usr/bin/env python3
# ============================================================
#  web_falso.py — Servidor Web de Phishing para Demo Visual
#  Tesis: Evaluación de la robustez de DNSSEC y DNS tradicional
#         frente a técnicas de envenenamiento de caché
#  UTN — Brian Steve Rea Arias
#
#  Descripción:
#    Simula el sitio web corporativo legítimo (empresa.local)
#    desde el nodo ATACANTE. Cuando el caché DNS está
#    envenenado, los clientes son redirigidos aquí en lugar
#    del servidor web real (192.168.30.80).
#    Útil para la demo visual con Lubuntu en la defensa.
#
#  Uso:
#    python3 web_falso.py           # escucha en 0.0.0.0:80
#    python3 web_falso.py --puerto 8080
# ============================================================

import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

PUERTO   = 80
IP_LOCAL = "0.0.0.0"

HTML_PHISHING = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Portal Corporativo — empresa.local</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: Arial, sans-serif;
    background: #f0f2f5;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 20px;
  }
  .banner-alerta {
    width: 100%;
    max-width: 700px;
    background: #d32f2f;
    color: white;
    padding: 12px 20px;
    border-radius: 6px;
    margin-bottom: 20px;
    font-size: 13px;
    font-weight: bold;
    text-align: center;
    letter-spacing: 0.5px;
  }
  .card {
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.12);
    padding: 40px;
    width: 100%;
    max-width: 700px;
  }
  .logo-area {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 30px;
    border-bottom: 2px solid #e0e0e0;
    padding-bottom: 20px;
  }
  .logo-icon {
    width: 48px;
    height: 48px;
    background: #1565c0;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-size: 22px;
    font-weight: bold;
  }
  .logo-text h1 { font-size: 20px; color: #1a1a2e; }
  .logo-text p  { font-size: 13px; color: #666; }
  .seccion {
    background: #fff8e1;
    border: 1px solid #ffe082;
    border-radius: 6px;
    padding: 16px 20px;
    margin-bottom: 20px;
  }
  .seccion h3 { color: #e65100; font-size: 14px; margin-bottom: 6px; }
  .seccion p  { color: #555; font-size: 13px; line-height: 1.6; }
  .datos-ataque {
    background: #fce4ec;
    border: 1px solid #f48fb1;
    border-radius: 6px;
    padding: 16px 20px;
    margin-bottom: 20px;
  }
  .datos-ataque h3 { color: #880e4f; font-size: 14px; margin-bottom: 10px; }
  .dato-fila {
    display: flex;
    justify-content: space-between;
    font-size: 13px;
    padding: 4px 0;
    border-bottom: 1px solid #f8bbd0;
  }
  .dato-fila:last-child { border-bottom: none; }
  .dato-label { color: #888; }
  .dato-valor { color: #333; font-family: monospace; font-weight: bold; }
  .footer {
    margin-top: 20px;
    font-size: 12px;
    color: #999;
    text-align: center;
  }
  .badge {
    display: inline-block;
    background: #d32f2f;
    color: white;
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 3px;
    margin-left: 8px;
    vertical-align: middle;
  }
</style>
</head>
<body>

<div class="banner-alerta">
  ⚠ SERVIDOR FALSO — ATAQUE DE ENVENENAMIENTO DE CACHÉ DNS ACTIVO — UTN TESIS 2026
</div>

<div class="card">

  <div class="logo-area">
    <div class="logo-icon">E</div>
    <div class="logo-text">
      <h1>Portal Corporativo <span class="badge">FALSO</span></h1>
      <p>empresa.local — Simulación de ataque DNS Cache Poisoning</p>
    </div>
  </div>

  <div class="seccion">
    <h3>¿Qué ocurrió?</h3>
    <p>
      El caché del servidor DNS recursivo (192.168.20.10) fue envenenado mediante
      un <strong>ataque Kaminsky</strong>. El registro A de <code>web-corporativo.empresa.local</code>
      fue reemplazado por la IP del atacante (192.168.10.66), por lo que este navegador
      fue redirigido a este servidor en lugar del servidor web legítimo (192.168.30.80).
    </p>
  </div>

  <div class="datos-ataque">
    <h3>Datos del ataque interceptado</h3>
    <div class="dato-fila">
      <span class="dato-label">Servidor web legítimo</span>
      <span class="dato-valor">192.168.30.80</span>
    </div>
    <div class="dato-fila">
      <span class="dato-label">IP inyectada en caché</span>
      <span class="dato-valor">192.168.10.66 (atacante)</span>
    </div>
    <div class="dato-fila">
      <span class="dato-label">Dominio afectado</span>
      <span class="dato-valor">web-corporativo.empresa.local</span>
    </div>
    <div class="dato-fila">
      <span class="dato-label">Técnica empleada</span>
      <span class="dato-valor">Kaminsky (E3) / ARP+DNS Spoof (E5)</span>
    </div>
    <div class="dato-fila">
      <span class="dato-label">Protección DNSSEC</span>
      <span class="dato-valor">DESACTIVADA (escenario E3)</span>
    </div>
    <div class="dato-fila">
      <span class="dato-label">Timestamp</span>
      <span class="dato-valor" id="ts">cargando...</span>
    </div>
  </div>

  <div class="seccion">
    <h3>¿Cómo lo previene DNSSEC?</h3>
    <p>
      Con DNSSEC activo (E4), el recursivo valida las firmas RRSIG de cada respuesta
      usando la KSK del autoritativo. Las respuestas falsas del atacante no tienen
      firmas válidas, por lo que el recursivo retorna SERVFAIL y el caché
      <strong>no es envenenado</strong>.
    </p>
  </div>

  <div class="footer">
    Tesis: "Evaluación de la robustez de DNSSEC y DNS tradicional frente a técnicas
    de envenenamiento de caché en un entorno de simulación" — UTN 2026 — Brian Steve Rea Arias
  </div>

</div>

<script>
  document.getElementById('ts').textContent = new Date().toLocaleTimeString('es-EC');
</script>
</body>
</html>
"""

class ServidorFalso(BaseHTTPRequestHandler):

    def do_GET(self):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"  [{ts}] Conexión desde {self.client_address[0]} → {self.path}")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Servidor", "FALSO-ATACANTE-TESIS-UTN")
        self.end_headers()
        self.wfile.write(HTML_PHISHING.encode("utf-8"))

    def log_message(self, format, *args):
        pass  # silenciar log por defecto de HTTPServer

def main():
    global PUERTO

    parser = argparse.ArgumentParser(description="Servidor Web Falso — Tesis UTN")
    parser.add_argument("--puerto", type=int, default=PUERTO)
    args = parser.parse_args()
    PUERTO = args.puerto

    print("=" * 60)
    print("  SERVIDOR WEB FALSO — Demo visual envenenamiento DNS")
    print(f"  Escuchando en {IP_LOCAL}:{PUERTO}")
    print(f"  Simula: http://web-corporativo.empresa.local")
    print()
    print("  Requisito: caché del recursivo envenenado (E3)")
    print("  o ARP + DNS spoofing activos (E5)")
    print("  Ctrl+C para detener")
    print("=" * 60)
    print()

    try:
        servidor = HTTPServer((IP_LOCAL, PUERTO), ServidorFalso)
        servidor.serve_forever()
    except PermissionError:
        print(f"  [ERROR] Puerto {PUERTO} requiere privilegios.")
        print(f"  Usar: python3 web_falso.py --puerto 8080")
    except KeyboardInterrupt:
        print("\n  Servidor detenido.")

if __name__ == "__main__":
    main()
