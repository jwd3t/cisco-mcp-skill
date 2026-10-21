---
name: cisco-packettracer
description: Herramienta universal para descifrar, parsear e inspeccionar archivos de Cisco Packet Tracer (.pka, .pkt) a XML y JSON estructurado sin abrir la interfaz gráfica. Extrae topología, interfaces Cisco IOS (modos access/trunk, VLANs, IPs), enlaces y zonas visuales.
---

# Skill: Cisco Packet Tracer Inspector & Decryptor
> Herramienta universal y multiplataforma para analizar simulaciones de Cisco Packet Tracer (`.pka`, `.pkt`, `.xml`) por línea de comandos o mediante scripts de Python.

---

## 1. Descripción y Capacidades

Esta skill permite a desarrolladores, ingenieros de redes y agentes de inteligencia artificial procesar cualquier topología de Cisco Packet Tracer en **menos de 3 segundos** sin necesidad de abrir la aplicación de escritorio de Cisco:

1. **Descifrado Criptográfico Puro (`unpacket.py`):**
   Descifra la ofuscación binaria propietaria de Packet Tracer (Twofish / AES / XOR) y extrae el XML original en texto plano.
2. **Parseador Semántico a JSON (`packettracer_parser.py`):**
   Convierte el XML crudo (que suele pesar entre 15 y 50 MB) en un archivo JSON semántico ultraligero (reducción del 97%), estructurado y listo para auditorías o automatizaciones.
3. **Inspector Rápido por Consola (`pt_cli.py`):**
   Muestra resúmenes instantáneos en la terminal: cantidad de routers, switches, interfaces troncales, VLANs activas, direcciones IP y cableado.

---

## 2. Guía Rápida de Uso (CLI)

### 2.1 Descifrar `.pka` o `.pkt` a XML legible
```bash
# Genera automáticamente <archivo>_raw.xml
python scripts/unpacket.py topologia.pka

# O especificando el archivo de salida
python scripts/unpacket.py topologia.pka -o salida.xml
```

### 2.2 Convertir a JSON Estructurado
```bash
# Descifra y parsea directamente en un solo paso
python scripts/packettracer_parser.py topologia.pka -o topologia.json

# Opcional: exportar el XML y el JSON al mismo tiempo
python scripts/packettracer_parser.py topologia.pka -o topologia.json --export-xml topologia_raw.xml
```

### 2.3 Resumen Rápido en Terminal
```bash
# Ver conteo de routers, switches, VLANs y enlaces
python scripts/pt_cli.py summary topologia.pka

# Listar todos los dispositivos y sus clústeres
python scripts/pt_cli.py devices topologia.pka

# Listar los enlaces físicos puerto a puerto
python scripts/pt_cli.py links topologia.pka
```

---

## 3. Uso en Scripts de Python

Puedes importar el motor como librería en cualquier proyecto:

```python
from packettracer_parser import parse_file

# Carga y descifra al vuelo cualquier archivo
network = parse_file("topologia.pka")

print("Dispositivos:", network["metadata"]["devices_count"])
for dev in network["devices"]:
    if "switch" in dev.get("type", "").lower():
        print(f"Switch: {dev['name']} - VLANs: {dev.get('vlans_created')}")
```

---

## 4. Estructura de Salida JSON

El archivo JSON generado contiene los siguientes bloques:

* **`metadata`:** Cantidad de equipos, versión de Packet Tracer, número de enlaces y clústeres.
* **`devices`:** 
  * Nombre, modelo, tipo de equipo (`Router`, `Switch`, `PC`, `Server`, etc.).
  * Posición lógica (`x`, `y`) y pertenencia a clústeres (`cluster_name`).
  * Lista de interfaces físicas y lógicas con:
    * `mode`: `access` o `trunk`
    * `access_vlan`: Número de VLAN
    * `native_vlan`: VLAN nativa del troncal
    * `portfast`: `true` si tiene spanning-tree portfast activado
    * `ip` y `mask`: Direccionamiento IPv4
* **`links`:** Cableado puerto a puerto (`device1:port1` $\leftrightarrow$ `device2:port2`) y medio físico (`eCopper`, `eSerial`, `Fiber`).
* **`visual_zones`:** Detección de cajas y elipses de colores con clasificación RGB.
* **`clusters`:** Carpetas lógicas de agrupación de equipos.

---

## 5. Instalación y Compartición

Para compartir esta skill con compañeros o usarla en otro entorno de Antigravity:
1. Copia la carpeta `cisco-packettracer` dentro de:
   * **A nivel de proyecto:** `<tu_proyecto>/.agents/skills/cisco-packettracer/`
   * **A nivel global (para todos tus proyectos):** `~/.gemini/config/skills/cisco-packettracer/`
2. ¡Listo! Antigravity reconocerá automáticamente la skill y sus comandos.
