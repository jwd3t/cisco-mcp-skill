#!/usr/bin/env python3
"""
Packet Tracer Advanced Semantic Parser: .pka / .pkt / .xml -> 100% Complete Network JSON
Universal parser for Cisco Packet Tracer simulations.

Features:
- Accepts .pka, .pkt (auto-decrypts in memory) or raw .xml.
- Robust XML sanitization (handles invalid control bytes, unescaped ampersands).
- Extracts 100% of network devices (routers, switches, multilayer, PCs, servers, APs).
- Full Cisco IOS Configuration Parsing:
  * Hostnames, SVIs (IP/mask), Default Gateway
  * Subinterfaces (dot1Q encapsulation, IP, mask, description)
  * Switchport modes (access/trunk, access VLAN, native VLAN, portfast, shutdown)
  * DHCP Pools (network, default-router, dns-server, excluded addresses)
  * Static Routes (prefix, mask, next-hop, metric)
- Complete Physical & Logical Cabling (Links):
  * Maps <FROM> and <TO> save-ref-id directly to device names
  * Resolves interface-to-interface connections
  * Injects direct connection lists into every device object
- Extracts visual color zones and network clusters.

Usage:
    python packettracer_parser.py network.pka -o network.json
    python packettracer_parser.py network.pka --export-xml network_raw.xml -o network.json
"""

import argparse
import json
import re
import sys
from pathlib import Path

# Locate Decipher package across workspace
SCRIPT_DIR = Path(__file__).resolve().parent
search_dirs = [
    SCRIPT_DIR,
    SCRIPT_DIR / "Decipher",
    SCRIPT_DIR / "scratch" / "Unpacket",
    SCRIPT_DIR / ".agents" / "skills" / "cisco-packettracer" / "scripts",
    SCRIPT_DIR / ".agents" / "skills" / "redes-grupo4" / "scripts",
    SCRIPT_DIR / "cisco-packettracer-skill" / "scripts",
    Path.cwd() / "scratch" / "Unpacket",
    Path.cwd() / ".agents" / "skills" / "cisco-packettracer" / "scripts",
    Path.cwd() / ".agents" / "skills" / "redes-grupo4" / "scripts",
    Path.cwd() / "cisco-packettracer-skill" / "scripts"
]
for d in search_dirs:
    if d.exists() and str(d) not in sys.path:
        sys.path.insert(0, str(d))

try:
    from Decipher.pt_crypto import decrypt_pkt
    HAS_DECIPHER = True
except ImportError:
    try:
        from pt_crypto import decrypt_pkt
        HAS_DECIPHER = True
    except ImportError:
        HAS_DECIPHER = False



def sanitize_xml(xml_bytes: bytes) -> str:
    """Sanitizes raw Packet Tracer XML string for safe processing."""
    text = xml_bytes.decode('utf-8', errors='ignore')
    # Remove control chars (XML 1.0 illegal bytes)
    text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', text)
    # Escape lone ampersands not part of valid entity
    text = re.sub(r'&(?!(amp|lt|gt|quot|apos);)', '&amp;', text)
    return text


def parse_running_config(lines):
    """Parses Cisco IOS running-config lines into structured dictionaries."""
    hostname = None
    def_gw = None
    subinterfaces = []
    svis = []
    dhcp_pools = []
    static_routes = []
    ports_cfg = {}
    
    cur_int = None
    cur_pool = None
    excluded_addrs = []
    
    seen_subints = set()
    seen_svis = set()
    seen_pools = set()
    seen_routes = set()

    for l in lines:
        s = l.strip()
        if not s or s == '!':
            continue
            
        if s.startswith('hostname '):
            hostname = s.split()[1]
            
        elif s.startswith('ip default-gateway '):
            def_gw = s.split()[2]
            
        elif s.startswith('ip dhcp excluded-address '):
            parts = s.split()
            ex = parts[3:] if len(parts) > 4 else [parts[3]]
            if ex not in excluded_addrs:
                excluded_addrs.append(ex)
            
        elif s.startswith('ip dhcp pool '):
            pname = s.split()[3]
            if pname not in seen_pools:
                cur_pool = {'name': pname, 'network': None, 'mask': None, 'default_router': None, 'dns_server': None}
                dhcp_pools.append(cur_pool)
                seen_pools.add(pname)
            else:
                cur_pool = next((p for p in dhcp_pools if p['name'] == pname), None)
            
        elif cur_pool and s.startswith('network '):
            parts = s.split()
            if len(parts) >= 3:
                cur_pool['network'] = parts[1]
                cur_pool['mask'] = parts[2]
                
        elif cur_pool and s.startswith('default-router '):
            cur_pool['default_router'] = s.split()[1]
            
        elif cur_pool and s.startswith('dns-server '):
            cur_pool['dns_server'] = s.split()[1]
            
        elif s.startswith('ip route '):
            parts = s.split()
            if len(parts) >= 5:
                r_key = (parts[2], parts[3], parts[4])
                if r_key not in seen_routes:
                    static_routes.append({
                        'prefix': parts[2],
                        'mask': parts[3],
                        'next_hop': parts[4],
                        'metric': parts[5] if len(parts) > 5 else '1'
                    })
                    seen_routes.add(r_key)
                
        elif s.startswith('interface '):
            cur_pool = None
            cur_int = ''.join(s.split()[1:])
            if '.' in cur_int:
                if cur_int not in seen_subints:
                    subinterfaces.append({
                        'name': cur_int,
                        'vlan': None,
                        'is_native': False,
                        'ip': None,
                        'mask': None,
                        'description': None
                    })
                    seen_subints.add(cur_int)
            elif cur_int.lower().startswith('vlan'):
                if cur_int.lower() not in seen_svis:
                    svis.append({
                        'name': cur_int,
                        'ip': None,
                        'mask': None
                    })
                    seen_svis.add(cur_int.lower())
            else:
                cur_int_key = cur_int.lower()
                if cur_int_key not in ports_cfg:
                    ports_cfg[cur_int_key] = {
                        'name': cur_int,
                        'mode': 'routed',
                        'access_vlan': None,
                        'native_vlan': None,
                        'portfast': False,
                        'shutdown': False,
                        'ip': None,
                        'mask': None,
                        'description': None
                    }
                
        elif cur_int and '.' in cur_int:
            # Subinterface parameters
            sub = next((x for x in subinterfaces if x['name'].lower() == cur_int.lower()), None)
            if sub:
                if s.startswith('encapsulation dot1Q '):
                    parts = s.split()
                    sub['vlan'] = int(parts[2]) if parts[2].isdigit() else parts[2]
                    if 'native' in s:
                        sub['is_native'] = True
                elif s.startswith('ip address '):
                    parts = s.split()
                    sub['ip'] = parts[2]
                    sub['mask'] = parts[3]
                elif s.startswith('description '):
                    sub['description'] = s[12:]
                
        elif cur_int and cur_int.lower().startswith('vlan'):
            # SVI parameters
            svi = next((x for x in svis if x['name'].lower() == cur_int.lower()), None)
            if svi:
                if s.startswith('ip address '):
                    parts = s.split()
                    svi['ip'] = parts[2]
                    svi['mask'] = parts[3]
                
        elif cur_int and cur_int.lower() in ports_cfg:
            p = ports_cfg[cur_int.lower()]
            if 'switchport mode access' in s:
                p['mode'] = 'access'
            elif 'switchport mode trunk' in s:
                p['mode'] = 'trunk'
            elif s.startswith('switchport access vlan '):
                p['mode'] = 'access'
                v = s.split()[-1]
                p['access_vlan'] = int(v) if v.isdigit() else v
            elif s.startswith('switchport trunk native vlan '):
                v = s.split()[-1]
                p['native_vlan'] = int(v) if v.isdigit() else v
            elif 'portfast' in s:
                p['portfast'] = True
            elif s == 'shutdown':
                p['shutdown'] = True
            elif s.startswith('ip address '):
                parts = s.split()
                p['ip'] = parts[2]
                p['mask'] = parts[3]
            elif s.startswith('description '):
                p['description'] = s[12:]


    return {
        'hostname': hostname,
        'default_gateway': def_gw,
        'subinterfaces': subinterfaces,
        'svis': [s for s in svis if s['ip'] is not None],
        'dhcp_pools': dhcp_pools,
        'dhcp_excluded': excluded_addrs,
        'static_routes': static_routes,
        'ports_config': ports_cfg
    }


def classify_color(r: int, g: int, b: int) -> str:
    """Classifies RGB color codes into semantic network zones."""
    if 130 <= r <= 175 and 145 <= g <= 190 and 110 <= b <= 155:
        return "Verde Oscuro / Oliva (Administración)"
    if 160 <= r <= 200 and g >= 240 and b >= 240:
        return "Celeste / Cian (Marketing)"
    if r >= 240 and 190 <= g <= 235 and b >= 240:
        return "Rosa Pastel / Lila (Finanzas)"
    if 180 <= r <= 220 and g >= 240 and 210 <= b <= 245:
        return "Verde Claro / Menta (Ventas)"
    if r >= 220 and 80 <= g <= 135 and 150 <= b <= 205:
        return "Fucsia / Magenta (WiFi Ejecutivos)"
    if 210 <= r <= 240 and 230 <= g <= 255 and b >= 250:
        return "Azul Suave / Pastel (WiFi Clientes)"
    if r >= 240 and g >= 240 and 190 <= b <= 235:
        return "Amarillo Claro (Servidores)"
    return f"RGB({r},{g},{b})"


def parse_packet_tracer_full(xml_text: str) -> dict:
    """Core parser that extracts devices, links, configs, and visual elements."""
    # 1. Device blocks
    engine_pos = [m.start() for m in re.finditer(r'<ENGINE>', xml_text)]
    engine_pos.append(len(xml_text))
    
    devices = []
    ref_to_dev = {}
    
    for i in range(len(engine_pos) - 1):
        chunk = xml_text[engine_pos[i]:engine_pos[i+1]]
        name_m = re.search(r'<NAME[^>]*>([^<]+)</NAME>', chunk)
        type_m = re.search(r'<TYPE[^>]*>([^<]+)</TYPE>', chunk)
        model_m = re.search(r'<MODEL[^>]*>([^<]+)</MODEL>', chunk)
        sref_m = re.search(r'<SAVE_REF_ID>([^<]+)</SAVE_REF_ID>', chunk)
        cluster_m = re.search(r'<DEVCLUSTERID>([^<]+)</DEVCLUSTERID>', chunk)
        
        if not name_m:
            continue
            
        name = name_m.group(1).strip()
        dtype = type_m.group(1).strip() if type_m else 'Unknown'
        model = model_m.group(1).strip() if model_m else None
        sref = sref_m.group(1).strip() if sref_m else None
        cluster_id = cluster_m.group(1).strip() if cluster_m else 'ROOT'
        
        # CLI Running Config
        lines = re.findall(r'<LINE>([^<]*)</LINE>', chunk)
        ios_cfg = parse_running_config(lines) if lines else {}
        
        # VLANs database
        vlans = set(re.findall(r'<VLAN\s+[^>]*name="([^"]+)"\s+number="([^"]+)"', chunk) + 
                    re.findall(r'<VLAN\s+number="([^"]+)"\s+name="([^"]+)"', chunk))
        vlan_list = []
        for v in vlans:
            num = v[0] if v[0].isdigit() else v[1]
            vname = v[1] if v[0].isdigit() else v[0]
            if num not in ['1', '1002', '1003', '1004', '1005']:
                vlan_list.append({'id': int(num), 'name': vname})
        vlan_list.sort(key=lambda x: x['id'])
        
        # Ports: combine IOS running config with XML hardware ports
        ports = list(ios_cfg.get('ports_config', {}).values())
        if not ports:
            port_chunks = re.findall(r'<PORT>(.*?)</PORT>', chunk, re.DOTALL)
            for pc in port_chunks:
                pname_m = re.search(r'<(?:PORT_NAME|NAME)>([^<]+)</(?:PORT_NAME|NAME)>', pc)
                if pname_m:
                    pname = pname_m.group(1).strip()
                    mac_m = re.search(r'<MACADDRESS>([^<]+)</MACADDRESS>', pc)
                    ip_m = re.search(r'<(?:IP|IP_ADDRESS)>([^<]+)</(?:IP|IP_ADDRESS)>', pc)
                    mask_m = re.search(r'<(?:SUBNET|SUBNET_MASK)>([^<]+)</(?:SUBNET|SUBNET_MASK)>', pc)
                    ports.append({
                        'name': pname,
                        'mac': mac_m.group(1).strip() if mac_m else None,
                        'ip': ip_m.group(1).strip() if ip_m and ip_m.group(1).strip() != '0.0.0.0' else None,
                        'mask': mask_m.group(1).strip() if mask_m and mask_m.group(1).strip() != '0.0.0.0' else None,
                        'mode': 'access'
                    })
            
        # End devices properties (PC, Laptop, Server, WirelessHost)
        ip_addrs = [ip for ip in re.findall(r'<IP_ADDRESS>([^<]+)</IP_ADDRESS>', chunk) if ip and ip != '0.0.0.0']
        gateways = [gw for gw in re.findall(r'<DEFAULT_GATEWAY>([^<]+)</DEFAULT_GATEWAY>', chunk) if gw and gw != '0.0.0.0']
        dns_servers = [d for d in re.findall(r'<DNS>([^<]+)</DNS>', chunk) if d and d != '0.0.0.0']
        dhcp_servers = [s for s in re.findall(r'<DHCP_SERVER_IP>([^<]+)</DHCP_SERVER_IP>', chunk) if s and s != '0.0.0.0']
        ssids = [s for s in re.findall(r'<SSID>([^<]+)</SSID>', chunk) if s]

        dev_data = {
            'name': name,
            'hostname': ios_cfg.get('hostname') or name,
            'type': dtype,
            'model': model,
            'save_ref_id': sref,
            'cluster_id': cluster_id,
            'vlans': vlan_list,
            'ports': ports,
            'subinterfaces': ios_cfg.get('subinterfaces', []),
            'svis': ios_cfg.get('svis', []),
            'default_gateway': ios_cfg.get('default_gateway') or (gateways[0] if gateways else None),
            'dhcp_pools': ios_cfg.get('dhcp_pools', []),
            'dhcp_excluded': ios_cfg.get('dhcp_excluded', []),
            'static_routes': ios_cfg.get('static_routes', []),
            'end_device_info': {
                'ip_addresses': ip_addrs,
                'gateways': gateways,
                'dns_servers': dns_servers,
                'dhcp_server': dhcp_servers[0] if dhcp_servers else None,
                'ssid': ssids[0] if ssids else None
            } if dtype in ['PC', 'Laptop', 'Server', 'PDA', 'WirelessHost'] else None,
            'links': []
        }
        devices.append(dev_data)
        if sref:
            ref_to_dev[sref] = dev_data

    # 2. Links / Cables
    link_chunks = re.findall(r'<LINK>(.*?)</LINK>', xml_text, re.DOTALL)
    links = []
    for lc in link_chunks:
        from_m = re.search(r'<FROM>([^<]+)</FROM>', lc)
        to_m = re.search(r'<TO>([^<]+)</TO>', lc)
        ports_m = re.findall(r'<PORT>([^<]+)</PORT>', lc)
        ctype_m = re.search(r'<TYPE>([^<]+)</TYPE>', lc)
        
        if from_m and to_m and len(ports_m) >= 2:
            sref1 = from_m.group(1).strip()
            p1 = ports_m[0].strip()
            sref2 = to_m.group(1).strip()
            p2 = ports_m[1].strip()
            ctype = ctype_m.group(1).strip() if ctype_m else 'Copper'
            
            d1 = ref_to_dev.get(sref1, {}).get('name', sref1)
            d2 = ref_to_dev.get(sref2, {}).get('name', sref2)
            
            link_obj = {
                'device1': d1,
                'port1': p1,
                'device2': d2,
                'port2': p2,
                'cable_type': ctype
            }
            links.append(link_obj)
            
            # Populate device links
            if sref1 in ref_to_dev:
                ref_to_dev[sref1]['links'].append(f"{p1} <--> {d2} ({p2})")
            if sref2 in ref_to_dev:
                ref_to_dev[sref2]['links'].append(f"{p2} <--> {d1} ({p1})")

    # 3. Clusters map
    clusters = {}
    for cl in re.finditer(r'<DEVCLUSTER>.*?<ID>([^<]+)</ID>.*?<NAME>([^<]+)</NAME>', xml_text, re.DOTALL):
        clusters[cl.group(1).strip()] = cl.group(2).strip()

    for d in devices:
        cid = d['cluster_id']
        d['cluster_name'] = clusters.get(cid, 'ROOT' if cid == 'ROOT' else cid)

    # 4. Visual zones
    visual_zones = []
    for shape in re.finditer(r'<(?:CANVAS_SHAPE|SHAPE)>.*?</(?:CANVAS_SHAPE|SHAPE)>', xml_text, re.DOTALL):
        s_chunk = shape.group(0)
        stype_m = re.search(r'<TYPE>([^<]+)</TYPE>', s_chunk)
        r_m = re.search(r'<(?:COLOR_R|R)>([^<]+)</(?:COLOR_R|R)>', s_chunk)
        g_m = re.search(r'<(?:COLOR_G|G)>([^<]+)</(?:COLOR_G|G)>', s_chunk)
        b_m = re.search(r'<(?:COLOR_B|B)>([^<]+)</(?:COLOR_B|B)>', s_chunk)
        if r_m and g_m and b_m:
            try:
                ri, gi, bi = int(r_m.group(1)), int(g_m.group(1)), int(b_m.group(1))
                visual_zones.append({
                    'shape': stype_m.group(1) if stype_m else 'Rectangle',
                    'color_rgb': [ri, gi, bi],
                    'label': classify_color(ri, gi, bi)
                })
            except ValueError:
                pass

    # 5. Summary metadata
    meta = {
        'total_devices': len(devices),
        'total_links': len(links),
        'total_clusters': len(clusters),
        'routers': len([d for d in devices if d['type'] == 'Router']),
        'switches': len([d for d in devices if d['type'] in ['Switch', 'MultiLayerSwitch']]),
        'pcs_and_hosts': len([d for d in devices if d['type'] in ['PC', 'Laptop', 'Server', 'PDA']]),
        'access_points': len([d for d in devices if 'Access Point' in d['type'] or 'AP' in d['name']])
    }

    return {
        'metadata': meta,
        'devices': devices,
        'links': links,
        'clusters': clusters,
        'visual_zones': visual_zones
    }


def parse_file(input_path: Path) -> dict:
    """Universal loader that auto-detects and decodes .pka, .pkt, or .xml."""
    input_path = Path(input_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Archivo no encontrado: {input_path}")

    ext = input_path.suffix.lower()
    if ext in [".pka", ".pkt"]:
        if not HAS_DECIPHER:
            raise RuntimeError("Se requiere el motor Decipher para descifrar archivos .pka / .pkt.")
        raw_bytes = input_path.read_bytes()
        decrypted = decrypt_pkt(raw_bytes)
        if isinstance(decrypted, str):
            decrypted = decrypted.encode("utf-8", errors="ignore")
        xml_str = sanitize_xml(decrypted)
        return parse_packet_tracer_full(xml_str)
    else:
        # Raw xml or plain file
        raw_bytes = input_path.read_bytes()
        xml_str = sanitize_xml(raw_bytes)
        return parse_packet_tracer_full(xml_str)


def main():
    parser = argparse.ArgumentParser(
        description="Parsea simulaciones Cisco Packet Tracer (.pka / .pkt / .xml) a JSON semántico 100% completo."
    )
    parser.add_argument("input", type=Path, help="Archivo .pka, .pkt o .xml a procesar.")
    parser.add_argument("-o", "--output", type=Path, help="Ruta del JSON resultante (opcional).", default=None)
    parser.add_argument("--export-xml", type=Path, help="Ruta opcional para exportar el XML descifrado.", default=None)
    parser.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso.")

    args = parser.parse_args()

    try:
        if args.export_xml and args.input.suffix.lower() in [".pka", ".pkt"]:
            raw_bytes = args.input.read_bytes()
            decrypted = decrypt_pkt(raw_bytes)
            if isinstance(decrypted, str):
                decrypted = decrypted.encode("utf-8", errors="ignore")
            cleaned_str = sanitize_xml(decrypted)
            args.export_xml.write_text(cleaned_str, encoding="utf-8")
            if not args.quiet:
                print(f"[+] XML descifrado exportado en: {args.export_xml}")

        data = parse_file(args.input)

        out_path = args.output or args.input.with_suffix(".json")
        out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

        if not args.quiet:
            print("=" * 60)
            print("  Cisco Packet Tracer Universal Parser (v2.0 Full Semantic)")
            print("=" * 60)
            print(f"Archivo Origen : {args.input.name}")
            print(f"Salida JSON    : {out_path.name}")
            print(f"Dispositivos   : {data['metadata']['total_devices']}")
            print(f"Routers        : {data['metadata']['routers']}")
            print(f"Switches       : {data['metadata']['switches']}")
            print(f"Enlaces Físicos: {data['metadata']['total_links']}")
            print(f"Clústers       : {data['metadata']['total_clusters']}")
            print("[+] ¡Procesamiento completado con éxito (100% enriquecido)!")

    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
