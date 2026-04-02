"""Auto-generate libfuzzer dictionaries from Wireshark dissector source."""

import re
from pathlib import Path
from typing import List, Set

from rich.console import Console

# Patterns to extract magic bytes and constants from C source
HEX_CONST_RE = re.compile(r'0x([0-9A-Fa-f]{2,8})\b')
STRING_LITERAL_RE = re.compile(r'"([A-Za-z][A-Za-z0-9_/\-\.]{2,30})"')

# Common protocol magic bytes by encap type
BUILTIN_DICTIONARIES = {
    # Ethernet (encap 1)
    1: [
        # EtherType values
        b'\x08\x00',  # IPv4
        b'\x86\xdd',  # IPv6
        b'\x08\x06',  # ARP
        b'\x81\x00',  # VLAN 802.1Q
        b'\x88\x47',  # MPLS unicast
        b'\x88\x48',  # MPLS multicast
        b'\x88\x63',  # PPPoE Discovery
        b'\x88\x64',  # PPPoE Session
        b'\x88\x8e',  # 802.1X
        b'\x88\xcc',  # LLDP
        b'\x88\xa8',  # 802.1ad (QinQ)
        # Common MAC OUI prefixes
        b'\xff\xff\xff\xff\xff\xff',  # Broadcast
        b'\x01\x00\x5e',  # IPv4 multicast
        b'\x33\x33',  # IPv6 multicast
    ],
    # Raw IP (encap 7)
    7: [
        # IPv4 header patterns
        b'\x45',      # IPv4, IHL=5
        b'\x46',      # IPv4, IHL=6
        b'\x60',      # IPv6
        # IP protocols
        b'\x06',      # TCP
        b'\x11',      # UDP
        b'\x01',      # ICMP
        b'\x3a',      # ICMPv6
        b'\x2f',      # GRE
        b'\x32',      # ESP
        b'\x33',      # AH
        b'\x59',      # OSPF
    ],
    # Raw IPv4 (encap 129)
    129: [
        b'\x45', b'\x46', b'\x47', b'\x48',
        b'\x06', b'\x11', b'\x01',
    ],
    # Raw IPv6 (encap 130)
    130: [
        b'\x60\x00\x00\x00',  # IPv6 header start
        b'\x3a',  # ICMPv6
        b'\x06',  # TCP
        b'\x11',  # UDP
    ],
    # SLL (Linux cooked, encap 25)
    25: [
        b'\x00\x00',  # packet type: to us
        b'\x00\x01',  # packet type: broadcast
        b'\x00\x04',  # packet type: outgoing
        b'\x08\x00',  # EtherType IPv4
        b'\x86\xdd',  # EtherType IPv6
    ],
    # IEEE 802.11 (encap 20)
    20: [
        b'\x80',  # Beacon
        b'\x40',  # Probe request
        b'\x50',  # Probe response
        b'\x00',  # Association request
        b'\x08',  # Data
        b'\x88',  # QoS Data
        b'\xc0',  # Deauthentication
        b'\xb0',  # Authentication
    ],
    # USB Linux (encap 95)
    95: [
        b'\x00\x00\x00\x00',  # URB function
        b'\x43',  # USB_DIR_OUT
        b'\x53',  # SUBMIT
        b'\x43',  # COMPLETE
    ],
}

# Generic tokens useful across all protocols
GENERIC_TOKENS = [
    b'\x00',
    b'\xff',
    b'\x00\x00',
    b'\xff\xff',
    b'\x00\x00\x00\x00',
    b'\xff\xff\xff\xff',
    b'\x7f',
    b'\x80',
    b'\x01',
    b'\x02',
    b'\x03',
    b'\x04',
]


def generate_dictionary(encap_id: int, output_path: Path,
                        extra_source_dirs: List[Path] = None,
                        console: Console = None):
    """Generate a libfuzzer dictionary file for a given encap type.

    Combines:
    1. Built-in protocol magic bytes for the encap type
    2. Generic fuzzing tokens
    3. Optionally: constants extracted from dissector source code
    """
    console = console or Console()
    tokens: Set[bytes] = set()

    # Built-in tokens for this encap
    if encap_id in BUILTIN_DICTIONARIES:
        for token in BUILTIN_DICTIONARIES[encap_id]:
            tokens.add(token)
        console.print(f"  Built-in tokens for encap {encap_id}: "
                      f"{len(BUILTIN_DICTIONARIES[encap_id])}")

    # Generic tokens
    for token in GENERIC_TOKENS:
        tokens.add(token)

    # Extract from source if available
    if extra_source_dirs:
        for src_dir in extra_source_dirs:
            extracted = _extract_tokens_from_source(src_dir)
            tokens.update(extracted)
            console.print(f"  Extracted from {src_dir}: {len(extracted)} tokens")

    # Write dictionary file
    lines = []
    lines.append(f"# wirefuzz dictionary for encap type {encap_id}")
    lines.append(f"# Generated tokens: {len(tokens)}")
    lines.append("")

    for i, token in enumerate(sorted(tokens, key=lambda t: (len(t), t))):
        hex_str = "".join(f"\\x{b:02x}" for b in token)
        lines.append(f'token_{i}="{hex_str}"')

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n")
    console.print(f"  Dictionary written: {output_path} ({len(tokens)} tokens)")


def _extract_tokens_from_source(src_dir: Path) -> Set[bytes]:
    """Extract hex constants and string literals from C source files."""
    tokens: Set[bytes] = set()

    for c_file in src_dir.rglob("*.c"):
        try:
            content = c_file.read_text(errors="ignore")
        except OSError:
            continue

        # Extract hex constants (2-8 hex chars = 1-4 bytes)
        for m in HEX_CONST_RE.finditer(content):
            hex_val = m.group(1)
            try:
                val = int(hex_val, 16)
                byte_len = (len(hex_val) + 1) // 2
                if 1 <= byte_len <= 4:
                    tokens.add(val.to_bytes(byte_len, "big"))
            except (ValueError, OverflowError):
                pass

        # Extract short string literals (potential protocol identifiers)
        for m in STRING_LITERAL_RE.finditer(content):
            s = m.group(1)
            if 3 <= len(s) <= 16:
                tokens.add(s.encode("ascii", errors="ignore"))

    return tokens
