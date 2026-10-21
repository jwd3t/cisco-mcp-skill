# Cisco Packet Tracer Inspector & Decryptor

> **Herramienta independiente en Python para descifrar, parsear y auditar archivos de Cisco Packet Tracer (`.pka`, `.pkt`, `.xml`) sin abrir la interfaz gráfica.**

Compatible con Windows, Linux y macOS. Diseñado tanto para uso directo en terminal como para integrarse como **Skill de Google Antigravity**.

---

## 🚀 Inicio Rápido

### Requisitos:
* Python 3.8 o superior.
* No requiere dependencias externas obligatorias (utiliza librerías estándar de Python).

### 1. Resumen rápido de una topología
```bash
python scripts/pt_cli.py summary mi_red.pka
```

### 2. Descifrar `.pka` o `.pkt` a XML en texto plano
```bash
python scripts/unpacket.py mi_red.pka
# Genera: mi_red_raw.xml
```

### 3. Convertir la red a JSON estructurado (Reducción del 97%)
```bash
python scripts/packettracer_parser.py mi_red.pka -o mi_red.json
```

---

## 📦 Cómo compartir e instalar como Skill de Antigravity

Si utilizas **Google Antigravity (AGY)** y quieres que el agente reconozca automáticamente tus archivos de Packet Tracer:

### Opción 1: En un proyecto específico
Copia esta carpeta completa dentro de tu repositorio o proyecto:
```text
mi_proyecto/
  ├── .agents/
  │    └── skills/
  │         └── cisco-packettracer/
  │              ├── SKILL.md
  │              └── scripts/
```

### Opción 2: Para todos tus proyectos (Global)
Copia esta carpeta en tu configuración global de Antigravity:
* **Windows:** `C:\Users\<tu_usuario>\.gemini\config\skills\cisco-packettracer\`
* **Linux/macOS:** `~/.gemini/config/skills/cisco-packettracer/`

---

## 🛠️ Herramientas Incluidas

* **`scripts/unpacket.py`:** Motor de descifrado criptográfico que rompe la ofuscación de Cisco Packet Tracer.
* **`scripts/packettracer_parser.py`:** Extrae dispositivos, interfaces IOS (`access`, `trunk`, VLAN nativa, `portfast`), direcciones IP, cableado puerto a puerto y zonas de color.
* **`scripts/pt_cli.py`:** CLI interactiva para consultar resúmenes, lista de equipos y enlaces directamente en la terminal.
* **`scripts/Decipher/`:** Biblioteca pura en Python de algoritmos criptográficos (Twofish, EAX, CTR, CMAC).

---

## 📄 Licencia
Libre para uso educativo, académico y profesional.
