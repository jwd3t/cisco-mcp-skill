# Cisco Packet Tracer MCP & Agent Skill (`cisco-mcp-skill`)

> **Herramienta independiente en Python para descifrar, parsear y auditar archivos de Cisco Packet Tracer (`.pka`, `.pkt`, `.xml`) sin necesidad de abrir la aplicación de escritorio.**

Diseñado para uso directo por línea de comandos (CLI) o para integrarse como **Skill / Plugin en Google Antigravity, Gemini CLI, Claude Code y OpenAI Agents**.

---

## ⚡ Capacidades Principales

1. **Descifrado Criptográfico Puro (`unpacket.py`):**
   - Rompe la ofuscación binaria propietaria de Cisco Packet Tracer (Twofish / AES / XOR) y genera el XML original en texto plano en menos de 2 segundos.
2. **Parseador Semántico a JSON (`packettracer_parser.py`):**
   - Convierte archivos `.pkt`, `.pka` o `.xml` (15-50 MB) en archivos JSON semánticos ultraligeros (~30 KB, reducción del 97%).
   - Extrae automáticamente: topología completa, interfaces Cisco IOS (modos access/trunk, VLAN nativa, portfast), subinterfaces, SVIs, direcciones IP, máscaras de subred, gateways, cableado puerto a puerto y zonas visuales.
3. **Inspector Rápido por Consola (`pt_cli.py`):**
   - Muestra resúmenes instantáneos en la terminal: cantidad de routers, switches, enlaces físicos y direccionamiento.
4. **Skills y Plugin para Agentes de IA:**
   - Incluye las especificaciones `SKILL.md` y `plugin.json` listas para usar con slash commands (`/cisco-packettracer` y `/redes-grupo4`).

---

## 🚀 Uso Rápido por Consola

### Requisitos
* Python 3.8+ (No requiere librerías externas obligatorias, utiliza módulos estándar).

### 1. Resumen rápido de una topología
```bash
python3 pt_cli.py summary topologia.pkt
```

### 2. Descifrar `.pka` o `.pkt` a XML en texto plano
```bash
python3 unpacket.py topologia.pkt -o topologia_raw.xml
```

### 3. Convertir a JSON estructurado (enriquecido)
```bash
python3 packettracer_parser.py topologia.pkt -o topologia.json
```

---

## 📦 Instalación como Skill / Plugin en Google Antigravity

### Instalación Global (Disponible en todos los proyectos y por Slash Command)
Clona o copia el repositorio dentro del directorio de plugins o skills de Antigravity:

```bash
# Como plugin
git clone https://github.com/jwd3t/cisco-mcp-skill.git ~/.gemini/config/plugins/cisco-packettracer

# O directamente en skills
mkdir -p ~/.gemini/config/skills
cp -r skills/* ~/.gemini/config/skills/
```

### Uso en Chat / Slash Commands
Una vez instalado, puedes invocarlo directamente en cualquier conversación:
* `/cisco-packettracer` : Procesa cualquier topología, diagnostica problemas de red y genera tablas de direccionamiento.
* `/redes-grupo4` : Auditoría técnica de proyectos y laboratorios de redes.

---

## 📁 Estructura del Repositorio

```text
cisco-mcp-skill/
├── README.md                                # Documentación principal
├── plugin.json                              # Manifiesto de Plugin para Antigravity
├── unpacket.py                              # Motor de descifrado Packet Tracer a XML
├── packettracer_parser.py                   # Parser semántico XML/PKT/PKA a JSON
├── pt_cli.py                                # Interfaz de comandos para inspección
├── Decipher/                                # Implementación criptográfica Twofish/AES/EAX
├── skills/
│   ├── cisco-packettracer/
│   │   ├── SKILL.md                         # Definición de la skill cisco-packettracer
│   │   └── scripts/                         # Scripts asociados
│   └── redes-grupo4/
│       ├── SKILL.md                         # Definición de la skill redes-grupo4
│       └── scripts/                         # Scripts de auditoría
└── .agents/                                 # Soporte estándar para workspace agents
    └── skills/
```

---

## 📄 Licencia
MIT License. Libre para uso educativo, académico y profesional.
