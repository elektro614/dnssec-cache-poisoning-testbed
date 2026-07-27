# Evaluación de la robustez de DNSSEC frente a envenenamiento de caché

Entorno de simulación reproducible para comparar la resistencia de **DNSSEC** frente a **DNS tradicional** ante técnicas de envenenamiento de caché (cache poisoning), construido sobre GNS3 + Docker + BIND 9.

> Trabajo de titulación — Ingeniería en Telecomunicaciones, Universidad Técnica del Norte (Ibarra, Ecuador).
> Autor: Brian Steve Rea Arias · Director: Ing. Mauricio Domínguez Limaico · Asesor: Ing. Fabián Cuzme Rodríguez.

<!-- TODO: agrega aquí un badge o enlace al PDF de la tesis cuando esté publicada -->

## Resumen

Este laboratorio recrea una red empresarial con tres zonas (LAN, Tránsito y DMZ) y ejecuta cinco escenarios experimentales (E1–E5) que van desde el funcionamiento normal hasta ataques activos de envenenamiento de caché, midiendo la tasa de éxito del ataque, latencia, uso de CPU y tamaño de paquete. El objetivo es cuantificar, con evidencia reproducible, cuánta protección real aporta DNSSEC frente a un resolver sin validar.

## Topología

Red IPv4 con tres segmentos:

| Zona     | Subred            | Función                     |
|----------|-------------------|-----------------------------|
| LAN      | 192.168.10.0/24   | Clientes y atacante         |
| Tránsito | 192.168.20.0/24   | Resolver recursivo y sonda  |
| DMZ      | 192.168.30.0/24   | Servidores autoritativos    |

**Hosts:**

| Host              | IP             | Rol                          |
|-------------------|----------------|------------------------------|
| DNS Recursivo     | 192.168.20.10  | Resolver / caché             |
| Analizador        | 192.168.20.50  | Captura de tráfico (tshark)  |
| CLIENTE-1-1       | 192.168.10.10  | Cliente legítimo             |
| CLIENTE-1-2       | 192.168.10.30  | Cliente legítimo             |
| ATACANTE          | 192.168.10.66  | Origen de los ataques        |
| DNS Autoritativo  | 192.168.30.20  | Zona `empresa.local` (30 A)  |
| Esclavo           | 192.168.30.30  | Autoritativo secundario      |
| ServidorWeb       | 192.168.30.80  | Objetivo web                 |

<!-- TODO: inserta aquí el diagrama de topología (PNG) -->
<!-- ![Topología](docs/topologia.png) -->

## Stack técnico

- **GNS3** (routers Cisco C7200 / Dynamips) para el plano de red.
- **Docker** para los nodos DNS y clientes.
- **BIND 9.20.23** como servidor autoritativo, esclavo y recursivo.
- **DNSSEC:** algoritmo ECDSAP256SHA256 (Algoritmo 13), KSK ID 28475.
- **Análisis:** tshark / Scapy.

## Escenarios experimentales

| ID  | Descripción                                    |
|-----|------------------------------------------------|
| E1  | Operación normal (línea base, sin ataque)      |
| E2  | <!-- TODO: describe E2 --> |
| E3  | ARP + DNS spoofing                             |
| E4  | <!-- TODO: describe E4 --> |
| E5  | <!-- TODO: describe E5 --> |

## Resultados destacados

- **E3 (ARP + DNS spoofing):** tasa de envenenamiento de ~67–70 % sobre el resolver sin validación.
- **Ataque Kaminsky:** solo tiene efecto con el resolver en modo iterativo; en modo *forward-only* no prospera.
- <!-- TODO: agrega el resultado clave de DNSSEC vs tradicional (la comparación central de tu tesis) -->

<!-- TODO: inserta aquí las figuras de latencia / CPU / tamaño de paquete (300 dpi) -->

## Estructura del repositorio

```
.
├── scripts/
│   ├── restaurar-maestro.sh     # Restaura el estado limpio del testbed
│   ├── medir-avanzado.sh        # Recolección de métricas
│   ├── trafico-fondo.sh         # Tráfico de fondo (100/150/300 QPS)
│   └── verificar-kaminsky.sh    # Verificación del ataque Kaminsky
├── ataques/
│   ├── kaminsky.py
│   ├── dns_spoof.py
│   ├── arp_poison.py
│   └── web_falso.py
├── config/                      # Zonas y configs BIND (autoritativo, esclavo, recursivo)
├── resultados/                  # CSV de las mediciones E1–E5
├── docs/                        # Diagramas y figuras
└── README.md
```
<!-- TODO: ajusta esta estructura a como realmente tengas organizado el repo -->

## Cómo reproducirlo

<!-- TODO: pasos mínimos para que otra persona levante el laboratorio.
Ejemplo de esqueleto:
1. Importar el proyecto en GNS3.
2. Construir las imágenes Docker de config/.
3. Levantar la topología y verificar reachability.
4. Ejecutar restaurar-maestro.sh.
5. Correr el escenario deseado (E1–E5) y recolectar CSV.
-->

## Notas técnicas de implementación

- BIND 9.20 requiere `kill $(pgrep named)` para recargar (`rndc reload` no basta en este entorno).
- Los *trust anchors* deben declararse con `static-key`.
- Usar `dnssec-validation yes` (no `auto`) junto con `static-key`.
- Sal de NSEC3 generada con `openssl rand -hex 8` (los contenedores Debian 13 no traen `xxd`).

## Licencia

<!-- TODO: elige una licencia (MIT es habitual para trabajos académicos) -->

---

<!-- TODO: enlaza aquí tu portafolio / página personal cuando la tengas montada -->
