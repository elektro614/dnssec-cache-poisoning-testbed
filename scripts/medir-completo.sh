#!/bin/bash
# ============================================================
#  medir-completo.sh — Medición unificada de 5 escenarios
#  Tesis: Evaluación de la robustez de DNSSEC y DNS tradicional
#         frente a técnicas de envenenamiento de caché
#  UTN — Brian Steve Rea Arias
#
#  Debe correr en el nodo ANALIZADOR (192.168.20.50)
#
#  Uso:
#    bash /root/medir-completo.sh e1   # Escenario 1
#    bash /root/medir-completo.sh e2   # Escenario 2
#    bash /root/medir-completo.sh e3   # Escenario 3
#    bash /root/medir-completo.sh e4   # Escenario 4
#    bash /root/medir-completo.sh e5   # Escenario 5
#    bash /root/medir-completo.sh all  # Todos (solo E1 y E2 sin ataque)
#
#  Genera CSVs en /resultados/:
#    throughput_<escenario>.csv   — dnsperf QPS 200/300/500
#    latencia_<escenario>.csv     — latencia por consulta con dig
#    recursos_recursivo_<esc>.csv — CPU/RAM del recursivo
#    resumen_<escenario>.txt      — resumen legible
# ============================================================

set -e

ESCENARIO="${1:-help}"
SERVIDOR_DNS="192.168.20.10"
IP_RECURSIVO="192.168.20.10"
IP_ATACANTE="192.168.10.66"
DIR="/resultados"
mkdir -p "$DIR"

# Colores
OK()   { echo -e "\033[1;32m[OK]\033[0m  $1"; }
INFO() { echo -e "\033[1;34m[--]\033[0m  $1"; }
WARN() { echo -e "\033[1;33m[!!]\033[0m  $1"; }
SEP()  { echo "------------------------------------------------------"; }

# ============================================================
# ARCHIVO DE CONSULTAS PARA DNSPERF
# ============================================================

init_consultas() {
    cat > /tmp/consultas.txt << 'EOF'
web-corporativo.empresa.local A
correo.empresa.local A
mail.empresa.local A
webmail.empresa.local A
chat.empresa.local A
videoconf.empresa.local A
intranet.empresa.local A
wiki.empresa.local A
docs.empresa.local A
cloud.empresa.local A
sharepoint.empresa.local A
erp.empresa.local A
crm.empresa.local A
vpn.empresa.local A
ldap.empresa.local A
empresa.local SOA
empresa.local NS
EOF
}

# ============================================================
# FUNCIÓN: MEDIR THROUGHPUT CON DNSPERF
# ============================================================

medir_throughput() {
    local ESC=$1
    local CSV="${DIR}/throughput_${ESC}.csv"
    echo "escenario,qps_objetivo,enviadas,completadas,perdidas,throughput_real,latencia_media_ms,latencia_max_ms" > "$CSV"

    INFO "Midiendo throughput con dnsperf (200/300/500 QPS, 60s cada uno)..."

    for QPS in 200 300 500; do
        INFO "  dnsperf @ ${QPS} QPS — 60 segundos..."
        RESULTADO=$(dnsperf \
            -s "$SERVIDOR_DNS" \
            -d /tmp/consultas.txt \
            -l 60 \
            -Q "$QPS" \
            -c 3 2>&1) || true

        echo "$RESULTADO" > "/tmp/dnsperf_${ESC}_${QPS}qps.txt"

        ENVIADAS=$(echo "$RESULTADO"    | grep "Queries sent"       | awk '{print $NF}' | tr -d ',')
        COMPLETADAS=$(echo "$RESULTADO" | grep "Queries completed"  | awk '{print $NF}' | tr -d ',')
        PERDIDAS=$(echo "$RESULTADO"    | grep "Queries lost"       | awk '{print $NF}' | tr -d ',')
        THROUGHPUT=$(echo "$RESULTADO"  | grep "Queries per second" | awk '{print $NF}' | tr -d ',')
        LAT_MED=$(echo "$RESULTADO"     | grep "Average Latency"    | awk '{print $NF}' | sed 's/s//')
        LAT_MAX=$(echo "$RESULTADO"     | grep "Maximum Latency"    | awk '{print $NF}' | sed 's/s//')

        LAT_MED_MS=$(echo "scale=2; ${LAT_MED:-0} * 1000" | bc 2>/dev/null || echo "0")
        LAT_MAX_MS=$(echo "scale=2; ${LAT_MAX:-0} * 1000" | bc 2>/dev/null || echo "0")

        echo "${ESC},${QPS},${ENVIADAS:-0},${COMPLETADAS:-0},${PERDIDAS:-0},${THROUGHPUT:-0},${LAT_MED_MS},${LAT_MAX_MS}" >> "$CSV"
        OK "  ${QPS} QPS → throughput: ${THROUGHPUT:-?} q/s | latencia: ${LAT_MED_MS} ms"
    done

    OK "Throughput guardado: ${CSV}"
}

# ============================================================
# FUNCIÓN: MEDIR LATENCIA CON DIG POR CONSULTA
# ============================================================

medir_latencia() {
    local ESC=$1
    local N=${2:-200}
    local CSV="${DIR}/latencia_${ESC}.csv"

    DOMINIOS=(
        "web-corporativo" "correo" "mail" "webmail" "chat"
        "videoconf" "intranet" "wiki" "docs" "cloud"
        "sharepoint" "erp" "crm" "vpn" "ldap"
        "google" "facebook" "banco" "gobierno" "universidad"
        "portal" "api" "cdn" "backup" "monitor"
        "nomina" "contabilidad" "inventario" "firewall" "proxy"
    )
    TD=${#DOMINIOS[@]}

    echo "timestamp,escenario,dominio,latencia_ms,ip_recibida,tiene_rrsig,flag_ad,estado,tamaño_bytes" > "$CSV"

    INFO "Midiendo latencia con dig — ${N} consultas..."

    OK_C=0; SPOOF=0; FAIL=0; SUM=0; BSUM=0
    T0=$(date +%s%N)

    for i in $(seq 1 "$N"); do
        D="${DOMINIOS[$((RANDOM % TD))]}.empresa.local"
        S=$(date +%s%N)
        FULL=$(dig @"$SERVIDOR_DNS" "$D" A +dnssec +timeout=5 +tries=1 2>/dev/null) || true
        E=$(date +%s%N)
        LAT=$(( (E - S) / 1000000 ))
        SUM=$((SUM + LAT))

        IP=$(echo "$FULL" | grep -A2 "ANSWER SECTION" | grep -oE '([0-9]+\.){3}[0-9]+' | head -1)
        HAS_RRSIG="no"; HAS_AD="no"
        echo "$FULL" | grep -q "RRSIG"       && HAS_RRSIG="si"
        echo "$FULL" | grep "flags:" | grep -q " ad " && HAS_AD="si"
        MSG=$(echo "$FULL" | grep "MSG SIZE" | grep -oE '[0-9]+$')
        BSUM=$((BSUM + ${MSG:-0}))

        if   [ -z "$IP" ];                       then EST="fallida";            FAIL=$((FAIL+1))
        elif [[ "$IP" == "192.168.10.66" ]];      then EST="envenenado";         SPOOF=$((SPOOF+1))
        elif [ "$HAS_AD" = "si" ];               then EST="validada_dnssec";    OK_C=$((OK_C+1))
        elif [[ "$IP" == 192.168.30.* ]];         then EST="ok_sin_firma";       OK_C=$((OK_C+1))
        else                                          EST="respuesta_inesperada"; SPOOF=$((SPOOF+1))
        fi

        echo "$(date +%s),${ESC},${D},${LAT},${IP:-none},${HAS_RRSIG},${HAS_AD},${EST},${MSG:-0}" >> "$CSV"

        # Progreso cada 10%
        PASO=$((N / 10)); [ "$PASO" -eq 0 ] && PASO=1
        if [ $((i % PASO)) -eq 0 ]; then
            AVG=$((SUM / i))
            echo "  [$(( i * 100 / N ))%] ${i}/${N} — OK:${OK_C} Env:${SPOOF} Fail:${FAIL} Lat_avg:${AVG}ms"
        fi

        sleep 0.1
    done

    TF=$(date +%s%N)
    DUR=$(( (TF - T0) / 1000000000 ))
    [ "$DUR" -eq 0 ] && DUR=1
    RESP=$((N - FAIL))
    AVG_B=0; [ "$RESP" -gt 0 ] && AVG_B=$((BSUM / RESP))
    AVG_LAT=0; [ "$N" -gt 0 ] && AVG_LAT=$((SUM / N))

    SEP
    echo "  Escenario       : ${ESC}"
    echo "  Total consultas : ${N}"
    echo "  Duración        : ${DUR}s"
    echo "  Throughput      : $((N / DUR)) q/s"
    echo "  Latencia prom.  : ${AVG_LAT} ms"
    echo "  Tamaño paquete  : ${AVG_B} bytes"
    echo "  Validadas DNSSEC: ${OK_C}"
    echo "  Envenenadas     : ${SPOOF}"
    echo "  Fallidas        : ${FAIL}"
    if [ "$RESP" -gt 0 ]; then
        echo "  Tasa envenenamiento: $(echo "scale=1; $SPOOF * 100 / $RESP" | bc)%"
        echo "  Tasa éxito         : $(echo "scale=1; $OK_C * 100 / $RESP" | bc)%"
    fi
    SEP
    OK "Latencia guardada: ${CSV}"
}

# ============================================================
# FUNCIÓN: MONITOREAR CPU/RAM DEL RECURSIVO DURANTE PRUEBA
# ============================================================

medir_recursos() {
    local ESC=$1
    local DUR=${2:-180}
    local CSV="${DIR}/recursos_recursivo_${ESC}.csv"

    echo "timestamp,escenario,cpu_percent,ram_used_mb,ram_total_mb,named_cpu,named_ram_mb" > "$CSV"
    INFO "Monitoreando recursos del recursivo (${DUR}s)..."

    INI=$(date +%s)
    while [ $(( $(date +%s) - INI )) -lt "$DUR" ]; do
        CPU=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print 100 - $8}' || echo "0")
        RAM_T=$(free -m 2>/dev/null | awk '/Mem:/{print $2}' || echo "0")
        RAM_U=$(free -m 2>/dev/null | awk '/Mem:/{print $3}' || echo "0")
        PID=$(pgrep named 2>/dev/null | head -1 || true)
        if [ -n "$PID" ]; then
            NC=$(ps -p "$PID" -o %cpu --no-headers 2>/dev/null | tr -d ' ' || echo "0")
            NR=$(echo "scale=1; $(ps -p "$PID" -o rss --no-headers 2>/dev/null | tr -d ' ' || echo 0) / 1024" | bc 2>/dev/null || echo "0")
        else
            NC=0; NR=0
        fi
        echo "$(date +%s),${ESC},${CPU},${RAM_U},${RAM_T},${NC},${NR}" >> "$CSV"
        sleep 2
    done
    OK "Recursos guardados: ${CSV}"
}

# ============================================================
# FUNCIÓN: GENERAR RESUMEN TXT
# ============================================================

generar_resumen() {
    local ESC=$1
    local RESUMEN="${DIR}/resumen_${ESC}.txt"
    {
        echo "======================================================"
        echo "  RESUMEN — Escenario: ${ESC}"
        echo "  Fecha: $(date)"
        echo "======================================================"
        echo ""
        if [ -f "${DIR}/throughput_${ESC}.csv" ]; then
            echo "--- THROUGHPUT (dnsperf) ---"
            cat "${DIR}/throughput_${ESC}.csv"
            echo ""
        fi
        if [ -f "${DIR}/latencia_${ESC}.csv" ]; then
            echo "--- LATENCIA (primeras 5 filas) ---"
            head -6 "${DIR}/latencia_${ESC}.csv"
            echo "..."
            echo ""
            echo "--- ESTADÍSTICAS LATENCIA ---"
            awk -F',' 'NR>1 && $4>0 {
                sum+=$4; n++; if($4>max) max=$4; if(min=="" || $4<min) min=$4
            } END {
                if(n>0) printf "  Promedio: %.1f ms\n  Mínima:  %.1f ms\n  Máxima:  %.1f ms\n  Muestras: %d\n", sum/n, min, max, n
            }' "${DIR}/latencia_${ESC}.csv"
            echo ""
        fi
    } > "$RESUMEN"
    OK "Resumen generado: ${RESUMEN}"
}

# ============================================================
# FUNCIÓN: EXTRAER CSVs AL HOST (correr desde EndeavourOS)
# ============================================================

cmd_extraer() {
    echo ""
    INFO "Para extraer los resultados al host, correr en EndeavourOS:"
    echo ""
    echo "  mkdir -p ~/tesis-resultados"
    ANZ="GNS3.Analizador-1-1.4ea40237-00ee-4702-8a98-96b3a40cd57e"
    for ESC in e1 e2 e3 e4 e5; do
        echo "  docker cp ${ANZ}:/resultados/ ~/tesis-resultados/${ESC}/ 2>/dev/null || true"
    done
    echo ""
}

# ============================================================
# ESCENARIO 1 — DNS sin DNSSEC, sin ataque
# ============================================================

run_e1() {
    echo "======================================================"
    INFO "ESCENARIO 1 — DNS tradicional sin DNSSEC, sin ataque"
    INFO "Propósito: línea base de rendimiento"
    echo "======================================================"
    init_consultas

    # Throughput y latencia en paralelo con recursos
    medir_recursos e1 220 &
    PID_REC=$!

    medir_throughput e1
    medir_latencia e1 200

    wait "$PID_REC" 2>/dev/null || true
    generar_resumen e1

    echo ""
    OK "E1 completado. Archivos en ${DIR}/"
    cmd_extraer
}

# ============================================================
# ESCENARIO 2 — DNS con DNSSEC, sin ataque
# ============================================================

run_e2() {
    echo "======================================================"
    INFO "ESCENARIO 2 — DNS con DNSSEC, sin ataque"
    INFO "Propósito: cuantificar overhead de DNSSEC"
    echo "======================================================"
    init_consultas

    medir_recursos e2 220 &
    PID_REC=$!

    medir_throughput e2
    medir_latencia e2 200

    wait "$PID_REC" 2>/dev/null || true
    generar_resumen e2

    echo ""
    OK "E2 completado."
    INFO "Comparar latencia_e1.csv vs latencia_e2.csv para cuantificar overhead DNSSEC."
    cmd_extraer
}

# ============================================================
# ESCENARIO 3 — Kaminsky SIN DNSSEC
# ============================================================

run_e3() {
    echo "======================================================"
    INFO "ESCENARIO 3 — Ataque Kaminsky sin DNSSEC"
    INFO "Propósito: demostrar vulnerabilidad DNS tradicional"
    echo "======================================================"
    WARN "REQUISITO: kaminsky.py debe estar corriendo en el ATACANTE"
    WARN "Si no está corriendo, Ctrl+C → lanzar ataque → repetir"
    echo ""
    read -p "  ¿El ataque Kaminsky está activo? [s/N]: " CONF
    [ "$CONF" != "s" ] && [ "$CONF" != "S" ] && { WARN "Abortado."; exit 1; }

    init_consultas

    medir_recursos e3 220 &
    PID_REC=$!

    medir_throughput e3
    medir_latencia e3 200

    wait "$PID_REC" 2>/dev/null || true
    generar_resumen e3

    echo ""
    OK "E3 completado."
    INFO "Revisar columna 'estado' en latencia_e3.csv — buscar 'envenenado'"
    cmd_extraer
}

# ============================================================
# ESCENARIO 4 — Kaminsky CON DNSSEC
# ============================================================

run_e4() {
    echo "======================================================"
    INFO "ESCENARIO 4 — Ataque Kaminsky con DNSSEC"
    INFO "Propósito: demostrar protección criptográfica de DNSSEC"
    echo "======================================================"
    WARN "REQUISITO: kaminsky.py debe estar corriendo en el ATACANTE"
    echo ""
    read -p "  ¿El ataque Kaminsky está activo? [s/N]: " CONF
    [ "$CONF" != "s" ] && [ "$CONF" != "S" ] && { WARN "Abortado."; exit 1; }

    init_consultas

    medir_recursos e4 220 &
    PID_REC=$!

    medir_throughput e4
    medir_latencia e4 200

    wait "$PID_REC" 2>/dev/null || true
    generar_resumen e4

    echo ""
    OK "E4 completado."
    INFO "Tasa de envenenamiento esperada: 0%"
    INFO "Flag AD esperado en todas las respuestas: si"
    cmd_extraer
}

# ============================================================
# ESCENARIO 5 — ARP + DNS Spoofing CON DNSSEC
# ============================================================

run_e5() {
    echo "======================================================"
    INFO "ESCENARIO 5 — ARP Spoofing + DNS Spoofing con DNSSEC"
    INFO "Propósito: evaluar limitaciones de DNSSEC en capa 2"
    echo "======================================================"
    WARN "REQUISITO: arp_poison.py Y dns_spoof.py deben estar corriendo"
    echo ""
    read -p "  ¿Los ataques ARP+DNS están activos? [s/N]: " CONF
    [ "$CONF" != "s" ] && [ "$CONF" != "S" ] && { WARN "Abortado."; exit 1; }

    init_consultas

    medir_recursos e5 220 &
    PID_REC=$!

    medir_throughput e5
    medir_latencia e5 200

    wait "$PID_REC" 2>/dev/null || true
    generar_resumen e5

    echo ""
    OK "E5 completado."
    INFO "DNSSEC bloquea envenenamiento vía recursivo → tasa 0% en caché"
    INFO "ARP intercepta tráfico capa 2 → ver capturas en Wireshark/Lubuntu"
    cmd_extraer
}

# ============================================================
# HELP
# ============================================================

cmd_help() {
    echo ""
    echo "  medir-completo.sh — Medición de 5 escenarios DNSSEC"
    echo "  Brian Steve Rea Arias — UTN 2026"
    echo ""
    echo "  Uso: bash /root/medir-completo.sh [ESCENARIO]"
    echo ""
    echo "  ESCENARIOS:"
    echo "    e1   DNS sin DNSSEC, sin ataque (línea base)"
    echo "    e2   DNS con DNSSEC, sin ataque"
    echo "    e3   Kaminsky sin DNSSEC  ← requiere ataque activo"
    echo "    e4   Kaminsky con DNSSEC  ← requiere ataque activo"
    echo "    e5   ARP+DNS con DNSSEC   ← requiere ataques activos"
    echo "    all  E1 y E2 automático (sin ataques)"
    echo ""
    echo "  RESULTADOS en /resultados/:"
    echo "    throughput_<esc>.csv"
    echo "    latencia_<esc>.csv"
    echo "    recursos_recursivo_<esc>.csv"
    echo "    resumen_<esc>.txt"
    echo ""
    echo "  EXTRAER al host (EndeavourOS):"
    echo "    docker cp GNS3.Analizador-1-1.<project-id>:/resultados/ ~/tesis-resultados/"
    echo ""
}

# ============================================================
# MAIN
# ============================================================

case "$ESCENARIO" in
    e1)   run_e1 ;;
    e2)   run_e2 ;;
    e3)   run_e3 ;;
    e4)   run_e4 ;;
    e5)   run_e5 ;;
    all)
        run_e1
        echo ""
        INFO "Pausa 30s antes de E2..."
        sleep 30
        run_e2
        ;;
    help|*) cmd_help ;;
esac
