#!/bin/bash
# ============================================================
#  /opt/scripts/prueba-completa.sh
#  Corre TODAS las pruebas de rendimiento DNS y genera CSVs
#  para el Capítulo 3 de la tesis.
#
#  Uso:
#    ./prueba-completa.sh sin_dnssec
#    ./prueba-completa.sh con_dnssec
#
#  Genera en /resultados/:
#    throughput_<escenario>.csv
#    latencia_<escenario>.csv
#    resumen_<escenario>.txt
# ============================================================

ESCENARIO="${1:-sin_dnssec}"
SERVIDOR="192.168.20.10"
DIR="/resultados"
mkdir -p $DIR

# Archivo de consultas para dnsperf
cat > /tmp/consultas.txt << 'EOF'
web-corporativo.empresa.local A
google.empresa.local A
facebook.empresa.local A
banco.empresa.local A
correo.empresa.local A
intranet.empresa.local A
empresa.local SOA
empresa.local NS
EOF

echo "======================================================"
echo "  PRUEBA COMPLETA — Escenario: $ESCENARIO"
echo "  Servidor: $SERVIDOR"
echo "  $(date)"
echo "======================================================"

# CSV de throughput
echo "escenario,carga_qps,queries_enviadas,queries_completadas,perdidas,throughput_qps,latencia_media_ms,latencia_max_ms" \
    > $DIR/throughput_${ESCENARIO}.csv

for QPS in 50 100 150 200 300; do
    echo ""
    echo "--- Prueba a $QPS QPS (60 segundos) ---"

    RESULTADO=$(dnsperf -s $SERVIDOR \
        -d /tmp/consultas.txt \
        -l 60 \
        -Q $QPS \
        -c 5 2>&1)

    echo "$RESULTADO" > /tmp/dnsperf_${QPS}qps.txt

    # Extraer métricas del output de dnsperf
    ENVIADAS=$(echo "$RESULTADO"   | grep "Queries sent"      | awk '{print $NF}')
    COMPLETADAS=$(echo "$RESULTADO"| grep "Queries completed" | awk '{print $NF}')
    PERDIDAS=$(echo "$RESULTADO"   | grep "Queries lost"      | awk '{print $NF}')
    THROUGHPUT=$(echo "$RESULTADO" | grep "Queries per second"| awk '{print $NF}')
    LAT_MEDIA=$(echo "$RESULTADO"  | grep "Average Latency"   | awk '{print $NF}' | sed 's/s//')
    LAT_MAX=$(echo "$RESULTADO"    | grep "Maximum Latency"   | awk '{print $NF}' | sed 's/s//')

    # Convertir segundos a ms
    LAT_MEDIA_MS=$(echo "scale=2; ${LAT_MEDIA:-0} * 1000" | bc 2>/dev/null || echo "0")
    LAT_MAX_MS=$(echo "scale=2; ${LAT_MAX:-0} * 1000"     | bc 2>/dev/null || echo "0")

    echo "$ESCENARIO,$QPS,${ENVIADAS:-0},${COMPLETADAS:-0},${PERDIDAS:-0},${THROUGHPUT:-0},${LAT_MEDIA_MS},${LAT_MAX_MS}" \
        >> $DIR/throughput_${ESCENARIO}.csv

    echo "  Enviadas: ${ENVIADAS} | Completadas: ${COMPLETADAS} | Pérdidas: ${PERDIDAS:-0}"
    echo "  Throughput: ${THROUGHPUT} qps | Latencia media: ${LAT_MEDIA_MS} ms"
done

# Resumen final
echo "" > $DIR/resumen_${ESCENARIO}.txt
echo "RESUMEN — Escenario: $ESCENARIO" >> $DIR/resumen_${ESCENARIO}.txt
echo "Fecha: $(date)" >> $DIR/resumen_${ESCENARIO}.txt
echo "" >> $DIR/resumen_${ESCENARIO}.txt
cat $DIR/throughput_${ESCENARIO}.csv >> $DIR/resumen_${ESCENARIO}.txt

echo ""
echo "======================================================"
echo "  Pruebas completadas"
echo "  CSV: $DIR/throughput_${ESCENARIO}.csv"
echo "  Resumen: $DIR/resumen_${ESCENARIO}.txt"
echo ""
echo "  Para copiar a tu PC:"
echo "    docker cp Analizador-1:/resultados/ ~/tesis-resultados/"
echo "======================================================"
