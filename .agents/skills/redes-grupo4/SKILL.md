---
name: redes-grupo4
description: Guía experta, arquitectura de red, direccionamiento IP (FLSM/VLSM), configuración Cisco Packet Tracer, dimensionamiento de switches y herramientas de auditoría automática para el proyecto final de Redes y Comunicaciones de Datos (Grupo 4 - UPC).
---

# Skill Maestra de Proyecto: Redes y Comunicaciones de Datos
> **Grupo 04 - UPC (Ciclo 2026-20)**  
> **Docente:** Milton Enrique Chinchay Celada  
> **Curso:** 1ASI0640 - Sección 7619  
> **Objetivo:** Guía técnica para implementar y verificar sedes en Cisco Packet Tracer (.pka).

---

## 1. Herramientas de Auditoría, Descifrado y Parsing Automático

Esta skill incluye una suite completa de ingeniería inversa, descifrado y auditoría en Python que procesa cualquier archivo de Packet Tracer (`.pka` o `.pkt`) en **3 segundos** sin abrir la aplicación.

### 1.1 `unpacket.py` — Descifrador de Packet Tracer a XML
Extrae el XML en texto plano a partir de cualquier archivo cifrado `.pka` o `.pkt`:
```bash
# Descifrar generando archivo <nombre>_raw.xml
python .agents/skills/redes-grupo4/scripts/unpacket.py PILOTO_PROY_G4_v3.pka

# O especificando la ruta del XML de salida
python .agents/skills/redes-grupo4/scripts/unpacket.py PILOTO_PROY_G4_v3.pka -o scratch/piloto_raw.xml
```

### 1.2 `packettracer_parser.py` — Parseador Avanzado a JSON Semántico (Reducción 97.4%)
Acepta directamente archivos `.pka`, `.pkt` (los descifra en memoria al vuelo) o archivos `.xml`.
Extrae en un solo JSON estructurado:
* **Topología y Cableado:** Dispositivos, enlaces puerto a puerto y tipos de medios.
* **Configuración Cisco IOS:** Modos `access`/`trunk`, VLANs de acceso, VLAN Nativa, `portfast`, `shutdown` e IPs configuradas.
* **Zonas Visuales de Color (Elipses y Rectángulos):** Clasifica los colores RGB en departamentos organizacionales oficiales (Verde Oscuro=Admin, Celeste=Marketing, Rosa Pastel=Finanzas, etc.) e indica qué PCs o switches están dentro de cada color.
* **Clústers:** Agrupaciones lógicas y pertenencia de dispositivos.

```bash
# Uso directo desde .pka o .pkt (descifra y parsea en 1 solo paso)
python .agents/skills/redes-grupo4/scripts/packettracer_parser.py PILOTO_PROY_G4_v3.pka -o scratch/piloto.network.json

# Opcional: exportar también el XML en el mismo comando
python .agents/skills/redes-grupo4/scripts/packettracer_parser.py PILOTO_PROY_G4_v3.pka -o scratch/piloto.network.json --export-xml scratch/piloto_raw.xml
```

### 1.3 `audit_pka.py` — Auditor Automático de Cumplimiento
Ejecuta la verificación de reglas del profesor Chinchay en 3 segundos:
```bash
python .agents/skills/redes-grupo4/scripts/audit_pka.py PILOTO_PROY_G4_v3.pka
```
**Qué audita automáticamente:**
1. **R-LIMA:** Subinterfaces dot1Q (110–190), direccionamiento IP y estado de los pools DHCP.
2. **Switches Multicapa (SWM01–SWM04):** VLANs creadas, troncales y VLAN Nativa 170.
3. **Switches de Acceso (Cisco 2960):** Detecta switches que aún permanezcan en VLAN 1 por defecto (observación crítica del docente).
4. **Dispositivos Finales:** Verifica qué PCs, laptops y smartphones han recibido IP por DHCP y cuál es su Gateway.


---

## 2. Arquitectura de Red y Direccionamiento IP

### 2.1 Jerarquía Corporativa (FLSM)
* **Bloque Multinacional:** `172.24.0.0/16` dividido en subredes `/19`:
  * Sede Matriz (Perú): `172.24.32.0/19`
* **Bloque Filial Perú:** `172.24.32.0/19` dividido en bloques `/22` (1 024 IPs cada uno):
  * WAN Enlaces Punto a Punto: `172.24.36.0/22` (subredes `/30`)
  * **Sede 1: Lima (Central):** `172.24.40.0/22`
  * **Sede 2: La Libertad:** `172.24.44.0/22`
  * **Sede 3: Ica:** `172.24.48.0/22`
  * **Sede 4: Huánuco:** `172.24.52.0/22`
  * **Sede 5: Puno:** `172.24.56.0/22`

---

### 2.2 Esquema de VLANs Oficial (Criterio del Docente: 3 Dígitos)
El primer dígito identifica la **Sede** (1=Lima, 2=La Libertad, 3=Ica, 4=Huánuco, 5=Puno) y los dos últimos identifican el **Área Organizacional**:

| Patrón | Área / Función | VLAN Lima | Red Lima (/N) | Gateway R-LIMA |
| :---: | :--- | :---: | :--- | :--- |
| **x10** | Administración | **VLAN 110** | `172.24.41.0 /25` | `172.24.41.1` |
| **x20** | Logística | **VLAN 120** | `172.24.42.0 /25` | `172.24.42.1` |
| **x30** | Finanzas | **VLAN 130** | `172.24.42.128 /26` | `172.24.42.129` |
| **x40** | Marketing | **VLAN 140** | `172.24.41.128 /25` | `172.24.41.129` |
| **x50** | Ventas | **VLAN 150** | `172.24.40.0 /24` | `172.24.40.1` |
| **x60** | Servidores Locales | **VLAN 160** | `172.24.43.0 /28` | `172.24.43.1` |
| **x70** | Nativa / Gestión Switches | **VLAN 170** | `172.24.43.64 /26` | `172.24.43.65` |
| **x80** | WiFi Clientes (Invitados) | **VLAN 180** | `172.24.42.224 /27` | `172.24.42.225` |
| **x90** | WiFi Ejecutivos (Dirección)| **VLAN 190** | `172.24.42.192 /27` | `172.24.42.193` |

---

## 3. Justificación del Dimensionamiento de Switches en Lima

### ¿Por qué el profesor y el Excel calculan 31 Switches?
Existen dos enfoques técnicos complementarios:

1. **Enfoque Global Topológico (El cálculo de pizarra del profesor):**
   * Total de 627 hosts proyectados en Lima $/ 24$ puertos $= 26.125 \longrightarrow \mathbf{27\text{ switches de acceso (2960)}}$.
   * Más los **4 switches Multicapa Capa 3** de Distribución (`SWM01_LI` Core, `SWM02_LI` WiFi, `SWM03_LI` Usuarios, `SWM04_LI` Servidores):
   $$\mathbf{27\text{ Acceso}} + \mathbf{4\text{ Multicapa}} = \mathbf{31\text{ switches totales en Lima}}$$

2. **Enfoque Modular por Rack Departamental (El cálculo de fórmulas en Excel):**
   * Cada departamento tiene sus propios switches en su propio rack (no se comparten puertos entre áreas por seguridad y límites físicos de cableado):
     * Ventas (193 hosts): 8 llenos + 1 fracción = **9 switches** (`SA01_LI` a `SA09_LI`)
     * Administración (122 hosts): 5 llenos + 1 fracción = **6 switches** (`SA10_LI` a `SA15_LI`)
     * Marketing (114 hosts): 4 llenos + 1 fracción = **5 switches** (`SA16_LI` a `SA20_LI`)
     * Logística (100 hosts): 4 llenos + 1 fracción = **5 switches** (`SA21_LI` a `SA25_LI`)
     * Finanzas (50 hosts): 2 llenos + 1 fracción = **3 switches** (`SA26_LI` a `SA28_LI`)
     * WiFi Ejecutivos / Clientes / Servidores: 1 fracción c/u = **3 switches** (`SA29_LI`, `SA30_LI`, `SA31_LI`)
     $$\mathbf{Total\text{ Switches de Acceso (2960)}} = 9 + 6 + 5 + 5 + 3 + 1 + 1 + 1 = \mathbf{31\text{ switches}}$$

---

## 4. Mapa Físico de Conexiones y Colores en Packet Tracer

### 4.1 Guía de Colores de la Capa de Acceso (De Izquierda a Derecha)
1. **Azul:** `VLAN 180` (WiFi Clientes: `Laptop1`, `Tablet PC0`).
2. **Magenta / Fucsia:** `VLAN 190` (WiFi Ejecutivos: `Smartphone0`, `Printer0`).
3. **Verde Claro:** `VLAN 150` (Ventas: `PC0`, `PC1`, `PC2` + Clúster de Ventas).
4. **Rosa Pastel:** `VLAN 130` (Finanzas: `PC3`).
5. **Celeste:** `VLAN 140` (Marketing: `PC4`).
6. **Verde Oscuro:** `VLAN 110` (Administración: `PC5`, `PC6` + Clúster de Administración).
7. **Amarillo:** `VLAN 160` (Servidores: `WEB`, `DNS`, `DHCP`, `FTP`, `MAIL`).

### 4.2 El Switch de Piso Compartido (`SA08_LI` / `Switch0(1)` sobre PC3)
Este switch físico conecta a 3 áreas a la vez mediante segmentación de puertos:
* `FastEthernet 0/1` $\rightarrow$ `PC2` (Verde Claro: `switchport access vlan 150`)
* `FastEthernet 0/2` $\rightarrow$ `PC3` (Rosa Pastel: `switchport access vlan 130`)
* `FastEthernet 0/3` $\rightarrow$ `PC4` (Celeste: `switchport access vlan 140`)
* `GigabitEthernet 0/1` $\rightarrow$ Troncal hacia `SWM03_LI` (VLAN Nativa 170).

---

## 5. Scripts Maestros de Configuración (Copiar y Pegar)

### 5.1 Router Central `R-LIMA` (Cisco 2911)
```cisco
enable
configure terminal
hostname R-LIMA
interface gigabitEthernet 0/0
 no shutdown
exit

! Subinterfaces 110 a 190
interface gigabitEthernet 0/0.110
 encapsulation dot1Q 110
 ip address 172.24.41.1 255.255.255.128
exit
interface gigabitEthernet 0/0.120
 encapsulation dot1Q 120
 ip address 172.24.42.1 255.255.255.128
exit
interface gigabitEthernet 0/0.130
 encapsulation dot1Q 130
 ip address 172.24.42.129 255.255.255.192
exit
interface gigabitEthernet 0/0.140
 encapsulation dot1Q 140
 ip address 172.24.41.129 255.255.255.128
exit
interface gigabitEthernet 0/0.150
 encapsulation dot1Q 150
 ip address 172.24.40.1 255.255.255.0
exit
interface gigabitEthernet 0/0.160
 encapsulation dot1Q 160
 ip address 172.24.43.1 255.255.255.240
exit
interface gigabitEthernet 0/0.170
 encapsulation dot1Q 170 native
 ip address 172.24.43.65 255.255.255.192
exit
interface gigabitEthernet 0/0.180
 encapsulation dot1Q 180
 ip address 172.24.42.225 255.255.255.224
exit
interface gigabitEthernet 0/0.190
 encapsulation dot1Q 190
 ip address 172.24.42.193 255.255.255.224
exit

! Pools DHCP
ip dhcp pool POOL_VENTAS
 network 172.24.40.0 255.255.255.0
 default-router 172.24.40.1
 dns-server 172.24.43.2
exit
ip dhcp pool POOL_ADMIN
 network 172.24.41.0 255.255.255.128
 default-router 172.24.41.1
 dns-server 172.24.43.2
exit
ip dhcp pool POOL_MARKETING
 network 172.24.41.128 255.255.255.128
 default-router 172.24.41.129
 dns-server 172.24.43.2
exit
ip dhcp pool POOL_FINANZAS
 network 172.24.42.128 255.255.255.192
 default-router 172.24.42.129
 dns-server 172.24.43.2
exit
ip dhcp pool POOL_WIFI_EJECUTIVOS
 network 172.24.42.192 255.255.255.224
 default-router 172.24.42.193
 dns-server 172.24.43.2
exit
ip dhcp pool POOL_WIFI_CLIENTES
 network 172.24.42.224 255.255.255.224
 default-router 172.24.42.225
 dns-server 172.24.43.2
exit
end
write memory
```

---

### 5.2 Switch Core de Distribución `SWM01_LI` (Catalyst 3650)
```cisco
enable
configure terminal
hostname SWM01_LI
vlan 110
 name Administracion
vlan 120
 name Logistica
vlan 130
 name Finanzas
vlan 140
 name Marketing
vlan 150
 name Ventas
vlan 160
 name Servidores
vlan 170
 name Nativa_Gestion
vlan 180
 name WiFi_Clientes
vlan 190
 name WiFi_Ejecutivos
exit
interface range gigabitEthernet 1/0/1 - 4
 switchport trunk native vlan 170
 switchport mode trunk
 switchport trunk allowed vlan 110,120,130,140,150,160,170,180,190
 no shutdown
exit
interface vlan 170
 ip address 172.24.43.66 255.255.255.192
 no shutdown
exit
ip default-gateway 172.24.43.65
end
write memory
```

---

### 5.3 Plantillas Rápidas para Switches de Acceso (Cisco 2960)

* **Switches de Administración (VLAN 110):**
  ```cisco
  enable
  configure terminal
  vlan 110
   name Administracion
  vlan 170
   name Nativa_Gestion
  exit
  interface range fa0/1 - 24
   switchport mode access
   switchport access vlan 110
   spanning-tree portfast
   no shutdown
  interface range gi0/1 - 2
   switchport mode trunk
   switchport trunk native vlan 170
   no shutdown
  end
  write
  ```

* **Switches de Ventas (VLAN 150):**
  ```cisco
  enable
  configure terminal
  vlan 150
   name Ventas
  vlan 170
   name Nativa_Gestion
  exit
  interface range fa0/1 - 24
   switchport mode access
   switchport access vlan 150
   spanning-tree portfast
   no shutdown
  interface range gi0/1 - 2
   switchport mode trunk
   switchport trunk native vlan 170
   no shutdown
  end
  write
  ```

---

## 6. Verificación y Pruebas Obligatorias en Packet Tracer

1. **Prueba DHCP:** Conectar una PC a un switch de acceso de cualquier departamento y verificar que obtenga IP y Gateway automáticamente.
2. **Prueba Inter-VLAN:** Hacer ping desde una PC de una VLAN hacia el Gateway y hacia otra PC de distinta VLAN dentro de la misma sede.
3. **Guardar el archivo:** Guardar el archivo `.pka` con los cambios listos.