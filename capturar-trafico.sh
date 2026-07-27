#!/bin/bash
# /opt/scripts/capturar-trafico.sh
# Captura tráfico DNS para analizar en Wireshark
# Uso: ./capturar-trafico.sh sin_dnssec 60

ESCENARIO="${1:-sin_dnssec}"
DURACION="${2:-60}"
ARCHIVO="/capturas/dns_${ESCENARIO}_$(date +%H%M%S).pcap"

echo "Capturando tráfico DNS por ${DURACION}s → $ARCHIVO"
echo "Abrir en Wireshark con: wireshark $ARCHIVO"
echo "(Ctrl+C para detener antes)"

tcpdump -i eth0 -w $ARCHIVO port 53 &
PID=$!
sleep $DURACION
kill $PID 2>/dev/null

echo ""
echo "Captura guardada: $ARCHIVO"
echo "Tamaño: $(du -h $ARCHIVO | cut -f1)"
echo ""
echo "Estadísticas básicas:"
tcpdump -r $ARCHIVO -nn 2>/dev/null | wc -l | xargs echo "  Total paquetes DNS:"
tcpdump -r $ARCHIVO -nn 2>/dev/null | grep -c "RRSIG\|DNSKEY\|NSEC" 2>/dev/null | xargs echo "  Paquetes DNSSEC:"
