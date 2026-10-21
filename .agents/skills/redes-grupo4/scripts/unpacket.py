#!/usr/bin/env python3
"""
Unpacket - Pure Python Cisco Packet Tracer (.pka / .pkt) Decryptor
Grupo 04 - UPC (Redes y Comunicaciones de Datos - 2026-20)

Usage:
    python unpacket.py archivo.pka
    python unpacket.py archivo.pkt -o archivo_raw.xml
"""

import argparse
import sys
import os
import re
from pathlib import Path

# Add current directory to path to locate Decipher
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

try:
    from Decipher.pt_crypto import decrypt_pkt
except ImportError:
    print("[-] Error: No se pudo importar el motor Decipher desde Decipher.pt_crypto.")
    sys.exit(1)


def clean_xml_bytes(data: bytes) -> bytes:
    """Removes invalid XML 1.0 control characters."""
    return re.sub(rb"[\x00-\x08\x0B\x0C\x0E-\x1F]", b"", data)


def main():
    parser = argparse.ArgumentParser(
        description="Descifra archivos binarios de Cisco Packet Tracer (.pka / .pkt) a XML legible."
    )
    parser.add_argument("input", type=Path, help="Archivo .pka o .pkt a descifrar.")
    parser.add_argument("-o", "--output", type=Path, help="Ruta del archivo XML resultante (opcional).", default=None)
    parser.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso.")

    args = parser.parse_args()

    if not args.input.exists():
        print(f"[-] Error: Archivo no encontrado: '{args.input}'")
        sys.exit(1)

    output_path = args.output
    if not output_path:
        stem = args.input.stem
        output_path = args.input.with_name(f"{stem}_raw.xml")

    if not args.quiet:
        print("=" * 60)
        print("  Unpacket - Motor de Descifrado Cisco Packet Tracer (UPC G4)")
        print("=" * 60)
        print(f"[*] Archivo origen : {args.input} ({args.input.stat().st_size:,} bytes)")

    try:
        raw_bytes = args.input.read_bytes()
        decrypted = decrypt_pkt(raw_bytes)
        if isinstance(decrypted, str):
            decrypted = decrypted.encode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[-] Error en el proceso de descifrado: {e}")
        sys.exit(1)

    cleaned = clean_xml_bytes(decrypted)

    try:
        output_path.write_bytes(cleaned)
        if not args.quiet:
            print(f"[+] Archivo XML guardado en : {output_path} ({len(cleaned):,} bytes)")
            print("[+] ¡Descifrado completado con éxito!")
    except IOError as e:
        print(f"[-] Error al guardar el archivo XML: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
