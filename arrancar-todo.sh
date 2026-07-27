#!/bin/bash
# Configura toda la topología de una vez
# Uso: bash arrancar-todo.sh

echo "=== Configurando topología DNS vs DNSSEC ==="

# Función para ejecutar comando en contenedor
run() {
    docker exec -it "$1" bash -c "$2" 2>/dev/null || echo "[$1] no disponible"
}

echo "[1/6] DNS Autoritativo..."
docker exec Servidor-DNS-AUTORITATIVO-1 bash -c '
ip addr flush dev eth0 2>/dev/null; ip addr add 192.168.30.20/24 dev eth0; ip link set eth0 up; ip route add default via 192.168.30.1 2>/dev/null
cat > /etc/bind/named.conf << CONF
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
CONF
named -u bind & sleep 2
ss -ulnp | grep :53 | head -1 && echo "OK autoritativo"
' 2>/dev/null

echo "[2/6] DNS Recursivo..."
docker exec Servidor-DNS-RECURSIVO-1 bash -c '
ip addr flush dev eth0 2>/dev/null; ip addr add 192.168.20.10/24 dev eth0; ip link set eth0 up; ip route add default via 192.168.20.1 2>/dev/null
cat > /etc/bind/named.conf << CONF
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
CONF
named -u bind & sleep 2
ss -ulnp | grep :53 | head -1 && echo "OK recursivo"
' 2>/dev/null

echo "[3/6] DNS Esclavo..."
docker exec Servidor-DNS-Esclavo-1 bash -c '
ip addr flush dev eth0 2>/dev/null; ip addr add 192.168.30.30/24 dev eth0; ip link set eth0 up; ip route add default via 192.168.30.1 2>/dev/null
cat > /etc/bind/named.conf << CONF
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
CONF
named -u bind & sleep 2
echo "OK esclavo"
' 2>/dev/null

echo "[4/6] Servidor Web..."
docker exec ServidorWeb-Corporativo-1 bash -c '
ip addr flush dev eth0 2>/dev/null; ip addr add 192.168.30.80/24 dev eth0; ip link set eth0 up; ip route add default via 192.168.30.1 2>/dev/null
echo "OK web"
' 2>/dev/null

echo "[5/6] Cliente y Atacante..."
docker exec CLIENTE-1-1 bash -c '
ip addr flush dev eth0 2>/dev/null; ip addr add 192.168.10.10/24 dev eth0; ip link set eth0 up; ip route add default via 192.168.10.1 2>/dev/null
echo "OK cliente"
' 2>/dev/null

docker exec ATACANTE-1-1 bash -c '
ip addr flush dev eth0 2>/dev/null; ip addr add 192.168.10.66/24 dev eth0; ip link set eth0 up; ip route add default via 192.168.10.1 2>/dev/null
echo "OK atacante"
' 2>/dev/null

echo "[6/6] Analizador..."
docker exec Analizador-1-1 bash -c '
ip addr flush dev eth0 2>/dev/null; ip addr add 192.168.20.50/24 dev eth0; ip link set eth0 up; ip route add default via 192.168.20.1 2>/dev/null
echo "OK analizador"
' 2>/dev/null

sleep 3
echo ""
echo "=== Verificando ==="
docker exec CLIENTE-1-1 bash -c 'dig @192.168.20.10 web-corporativo.empresa.local A +short' 2>/dev/null
echo "Si ves 192.168.30.80 arriba — todo está funcionando"
echo "=== Listo ==="
