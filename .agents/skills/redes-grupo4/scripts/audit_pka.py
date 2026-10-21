#!/usr/bin/env python3
"""
Master Audit Tool for Cisco Packet Tracer files (.pka / .pkt)
Grupo 04 - UPC (Redes y Comunicaciones de Datos - 2026-20)

Usage:
    python audit_pka.py <archivo.pka_o_pkt>
    python audit_pka.py PILOTO_PROY_G4_v3.pka
"""

import sys
import os
import re
import json
from pathlib import Path

# Add current dir to path to import Decipher
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

try:
    from Decipher.pt_crypto import decrypt_pkt
except ImportError:
    print("[-] Error: No se pudo importar el motor Decipher.")
    sys.exit(1)


def clean_xml_bytes(data: bytes) -> bytes:
    return re.sub(rb"[\x00-\x08\x0B\x0C\x0E-\x1F]", b"", data)


def audit_pka(pka_path: Path):
    if not pka_path.exists():
        print(f"[-] Archivo no encontrado: {pka_path}")
        return

    print("=" * 70)
    print(f"  AUDITORÍA TÉCNICA CISCO PACKET TRACER - GRUPO 04 (UPC)")
    print(f"  Archivo inspeccionado: {pka_path.name} ({pka_path.stat().st_size:,} bytes)")
    print("=" * 70)

    # 1. Decrypt
    print("\n[*] Descifrando archivo binario (.pka / .pkt)...")
    try:
        raw_data = pka_path.read_bytes()
        decrypted = decrypt_pkt(raw_data)
        if isinstance(decrypted, str):
            decrypted = decrypted.encode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[-] Error en el descifrado criptográfico: {e}")
        return

    xml_text = decrypted.decode('utf-8', errors='ignore')
    print(f"[+] Descifrado exitoso ({len(decrypted):,} bytes de XML extraído).")

    # 2. Check Router R-LIMA
    print("\n" + "-" * 70)
    print("1. ESTADO DEL ROUTER CENTRAL (R-LIMA)")
    print("-" * 70)
    m_rlima = re.search(r'<NAME[^>]*>RLIMA</NAME>(.*?)</DEVICE>', xml_text, re.DOTALL)
    if m_rlima:
        rlines = re.findall(r'<LINE>([^<]*)</LINE>', m_rlima.group(1))
        subints = [l.strip() for l in rlines if 'interface GigabitEthernet0/0.' in l]
        dot1q = [l.strip() for l in rlines if 'encapsulation dot1Q' in l]
        pools = [l.strip() for l in rlines if 'ip dhcp pool' in l]
        
        print(f"  Subinterfaces dot1Q detectadas: {len(subints)}")
        for s, d in zip(subints, dot1q):
            print(f"    - {s:30} -> {d}")
        
        print(f"\n  Pools DHCP configurados: {len(pools)}")
        for p in pools:
            print(f"    - {p}")
            
        has_3digits = any('110' in s or '150' in s for s in subints)
        if has_3digits:
            print("\n  [OK] R-LIMA está migrado al esquema oficial de 3 DÍGITOS (110-190).")
        else:
            print("\n  [ALERTA] R-LIMA aún tiene subinterfaces de 2 dígitos (10-90).")
    else:
        print("  [-] No se encontró el dispositivo RLIMA en la topología.")

    # 3. Check Multilayer Switches (SWM01 to SWM04)
    print("\n" + "-" * 70)
    print("2. ESTADO DE SWITCHES MULTICAPA DE DISTRIBUCIÓN (CAPA 3)")
    print("-" * 70)
    for swm in ['SWM01_LI', 'SWM02_LI', 'SWM03_LI', 'SWM04_LI']:
        m_swm = re.search(r'<NAME[^>]*>' + swm + r'</NAME>(.*?)</DEVICE>', xml_text, re.DOTALL)
        if m_swm:
            vlans = set(re.findall(r'<VLAN\s+name="([^"]+)"\s+number="([^"]+)"', m_swm.group(1)))
            vids = sorted([int(v[1]) for v in vlans if int(v[1]) < 1000])
            print(f"  {swm:10} | VLANs activas: {vids}")
        else:
            print(f"  {swm:10} | [-] No encontrado")

    # 4. Check Access Switches (detect VLAN 1 issues)
    print("\n" + "-" * 70)
    print("3. AUDITORÍA DE SWITCHES DE ACCESO (CISCO 2960) Y REGLA DE VLAN 1")
    print("-" * 70)
    dev_blocks = re.findall(r'<DEVICE[^>]*>(.*?)</DEVICE>', xml_text, re.DOTALL)
    access_switches = []
    for db in dev_blocks:
        name_m = re.search(r'<NAME[^>]*>([^<]+)</NAME>', db)
        type_m = re.search(r'<TYPE[^>]*>([^<]+)</TYPE>', db)
        if name_m and type_m and type_m.group(1).strip() == 'Switch':
            sname = name_m.group(1).strip()
            if not sname.startswith('SWM'):
                vlans = set(re.findall(r'<VLAN\s+name="([^"]+)"\s+number="([^"]+)"', db))
                vids = sorted([int(v[1]) for v in vlans if int(v[1]) < 1000])
                access_switches.append((sname, vids))

    print(f"  Total switches de acceso inspeccionados: {len(access_switches)}")
    vlan1_only = []
    configured_sws = []
    for sname, vids in access_switches:
        if vids == [1] or len(vids) <= 1:
            vlan1_only.append(sname)
        else:
            configured_sws.append((sname, vids))

    if configured_sws:
        print("\n  [OK] Switches de acceso configurados con VLANs:")
        for sname, vids in configured_sws:
            print(f"    - {sname:15} -> VLANs: {vids}")

    if vlan1_only:
        print(f"\n  [PENDIENTE] Switches que aún permanecen en VLAN 1 por defecto ({len(vlan1_only)} equipos):")
        for sname in vlan1_only[:12]:
            print(f"    - {sname:15} [Requiere asignar VLAN de acceso]")
        if len(vlan1_only) > 12:
            print(f"    ... y {len(vlan1_only) - 12} switches más.")

    # 5. Check End Devices (PCs, Laptops, Mobile)
    print("\n" + "-" * 70)
    print("4. CONECTIVIDAD Y DIRECCIONAMIENTO DE DISPOSITIVOS FINALES")
    print("-" * 70)
    for db in dev_blocks:
        name_m = re.search(r'<NAME[^>]*>([^<]+)</NAME>', db)
        if name_m:
            dname = name_m.group(1).strip()
            if any(k in dname for k in ['PC', 'Laptop', 'Smart', 'Tablet']):
                ips = re.findall(r'<IP_ADDRESS>([^<]+)</IP_ADDRESS>', db)
                dhcp = re.findall(r'<PORT_DHCP_ENABLE>([^<]+)</PORT_DHCP_ENABLE>', db)
                srv = re.findall(r'<DHCP_SERVER_IP>([^<]+)</DHCP_SERVER_IP>', db)
                ip_str = ips[0] if ips and ips[0] else "(Esperando DHCP)"
                srv_str = srv[0] if srv and srv[0] and srv[0] != "0.0.0.0" else "None"
                dhcp_str = "DHCP: ON" if dhcp and dhcp[0] == 'true' else "DHCP: OFF"
                print(f"  {dname:16} | {dhcp_str:10} | IP: {ip_str:18} | Gateway Server: {srv_str}")

    print("\n" + "=" * 70)
    print("  FIN DEL REPORTE DE AUDITORÍA")
    print("=" * 70)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
    else:
        # Default search in current directory
        defaults = [
            Path("PILOTO_PROY_G4_v3.pka"),
            Path("PILOTO_PROYv03.pka")
        ]
        target = next((p for p in defaults if p.exists()), None)
        if not target:
            print("[-] Uso: python audit_pka.py <archivo.pka>")
            sys.exit(1)

    audit_pka(target)
