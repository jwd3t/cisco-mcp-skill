#!/usr/bin/env python3
"""
Cisco Packet Tracer Fast CLI Inspector (v2.0 Enriquecido)
Quick summary and inspection tool for .pka, .pkt, and JSON files.

Usage:
    python pt_cli.py summary network.pka
    python pt_cli.py devices network.pka
    python pt_cli.py links network.pka
    python pt_cli.py vlans network.pka
"""

import argparse
import sys
from pathlib import Path

# Add current dir to path
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from packettracer_parser import parse_file

def print_summary(data: dict, filepath: Path):
    meta = data.get("metadata", {})
    devices = data.get("devices", [])
    links = data.get("links", [])
    clusters = data.get("clusters", {})
    zones = data.get("visual_zones", [])

    print("=" * 70)
    print(f"  RESUMEN DE TOPOLOGÍA CISCO PACKET TRACER")
    print(f"  Archivo: {filepath.name}")
    print("=" * 70)
    print(f"Total Dispositivos : {meta.get('total_devices', len(devices))}")
    print(f"Total Routers      : {meta.get('routers', 0)}")
    print(f"Total Switches     : {meta.get('switches', 0)}")
    print(f"Total Hosts/PCs    : {meta.get('pcs_and_hosts', 0)}")
    print(f"Total Enlaces      : {meta.get('total_links', len(links))}")
    print(f"Total Clústeres    : {len(clusters)}")
    print("-" * 70)

    # Routers
    routers = [d for d in devices if d.get("type") == "Router"]
    if routers:
        print(f"Routers detectados ({len(routers)}):")
        for r in sorted(routers, key=lambda x: x.get('name', '')):
            subints = r.get("subinterfaces", [])
            pools = r.get("dhcp_pools", [])
            routes = r.get("static_routes", [])
            print(f"  * {r.get('name'):<16} | Subinterfaces: {len(subints)} | DHCP Pools: {len(pools)} | Rutas: {len(routes)}")

    # Switches
    switches = [d for d in devices if d.get("type") in ["Switch", "MultiLayerSwitch"]]
    if switches:
        print(f"\nSwitches detectados ({len(switches)}):")
        for s in sorted(switches, key=lambda x: x.get('name', '')):
            vlans = [v.get("id") for v in s.get("vlans", [])]
            trunks = [p["name"] for p in s.get("ports", []) if p.get("mode") == "trunk"]
            svis = [f"{svi['name']}:{svi['ip']}" for svi in s.get("svis", []) if svi.get('ip')]
            svi_str = f" | SVI: {svis[0]}" if svis else ""
            print(f"  * {s.get('name'):<12} | VLANs: {len(vlans)} | Trunks: {len(trunks)}{svi_str}")

    print("=" * 70)


def print_devices(data: dict):
    print(f"{'Nombre':<16} | {'Hostname':<16} | {'Tipo':<16} | {'Clúster':<15}")
    print("-" * 70)
    for d in data.get("devices", []):
        name = d.get("name", "N/A")
        hostname = d.get("hostname", "N/A")
        dtype = d.get("type", "N/A")
        cluster = d.get("cluster_name", "ROOT")
        print(f"{name:<16} | {hostname:<16} | {dtype:<16} | {cluster:<15}")


def print_links(data: dict):
    print(f"{'Origen':<26} <---> {'Destino':<26} | Tipo Cable")
    print("-" * 70)
    for l in data.get("links", []):
        d1 = f"{l.get('device1')}:{l.get('port1')}"
        d2 = f"{l.get('device2')}:{l.get('port2')}"
        ctype = l.get("cable_type", "Copper")
        print(f"{d1:<26} <---> {d2:<26} | {ctype}")


def main():
    parser = argparse.ArgumentParser(description="Inspección rápida de archivos Cisco Packet Tracer.")
    parser.add_argument("command", choices=["summary", "devices", "links"], help="Comando a ejecutar.")
    parser.add_argument("file", type=Path, help="Archivo .pka, .pkt o .xml a inspeccionar.")

    args = parser.parse_args()

    try:
        data = parse_file(args.file)
        if args.command == "summary":
            print_summary(data, args.file)
        elif args.command == "devices":
            print_devices(data)
        elif args.command == "links":
            print_links(data)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
