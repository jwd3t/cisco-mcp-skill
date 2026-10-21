#!/usr/bin/env python3
"""
Unpacket - Pure Python Cisco Packet Tracer (.pka / .pkt) Decryptor
Universal tool for decrypting Packet Tracer files without opening the Cisco GUI.

Usage:
    python unpacket.py network.pka
    python unpacket.py network.pkt -o output_raw.xml
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


def decrypt_file(input_path: Path, output_path: Path = None, quiet: bool = False) -> Path:
    """
    Decrypts a .pka or .pkt file and writes the clean XML to output_path.
    Returns the Path to the generated XML file.
    """
    input_path = Path(input_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Archivo no encontrado: {input_path}")

    if not output_path:
        stem = input_path.stem
        output_path = input_path.with_name(f"{stem}_raw.xml")
    else:
        output_path = Path(output_path)

    if not quiet:
        print("=" * 60)
        print("  Unpacket - Motor Universal de Descifrado Cisco Packet Tracer")
        print("=" * 60)
        print(f"[*] Archivo origen : {input_path.name} ({input_path.stat().st_size:,} bytes)")

    raw_bytes = input_path.read_bytes()
    decrypted = decrypt_pkt(raw_bytes)
    if isinstance(decrypted, str):
        decrypted = decrypted.encode("utf-8", errors="ignore")

    cleaned = clean_xml_bytes(decrypted)
    output_path.write_bytes(cleaned)

    if not quiet:
        print(f"[+] Archivo XML guardado en : {output_path} ({len(cleaned):,} bytes)")
        print("[+] ¡Descifrado completado con éxito!")

    return output_path


def decrypt_bytes_to_xml(raw_bytes: bytes) -> str:
    """Decrypts in-memory .pka or .pkt bytes and returns the clean XML string."""
    decrypted = decrypt_pkt(raw_bytes)
    if isinstance(decrypted, str):
        decrypted = decrypted.encode("utf-8", errors="ignore")
    cleaned = clean_xml_bytes(decrypted)
    return cleaned.decode("utf-8", errors="ignore")


def main():
    parser = argparse.ArgumentParser(
        description="Descifra archivos de Cisco Packet Tracer (.pka / .pkt) a XML legible."
    )
    parser.add_argument("input", type=Path, help="Archivo .pka o .pkt a descifrar.")
    parser.add_argument("-o", "--output", type=Path, help="Ruta del archivo XML resultante (opcional).", default=None)
    parser.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso.")

    args = parser.parse_args()

    try:
        decrypt_file(args.input, args.output, quiet=args.quiet)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
