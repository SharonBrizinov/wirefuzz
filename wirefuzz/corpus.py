"""Corpus preparation: extract packets by encap type from PCAPs.

Reuses pcap/pcapng binary parsing patterns from wiremin's cmin.py.
"""

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from rich.console import Console
from rich.progress import Progress

from wirefuzz.encaps import EncapType

# -- pcap/pcapng magic numbers --
PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D
PCAP_MAGIC_NS_BE = 0x4DC3B2A1

PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_EPB = 0x00000006
PCAPNG_SPB = 0x00000003

# DLT (pcap link-layer type) to WTAP encap ID mapping.
# Sourced from wiretap/pcap-common.c in the Wireshark source tree.
# pcap files store DLT numbers; Wireshark uses its own WTAP_ENCAP_* IDs.
# We need this to correctly match packets when the user specifies a WTAP encap ID.
# fmt: off
_DLT_TO_WTAP: Dict[int, int] = {
    0:   15,  # DLT_NULL (BSD loopback) -> WTAP_ENCAP_NULL
    1:   1,   # ETHERNET -> WTAP_ENCAP_ETHERNET
    6:   2,   # TOKEN_RING -> WTAP_ENCAP_TOKEN_RING
    8:   3,   # SLIP -> WTAP_ENCAP_SLIP
    9:   4,   # PPP -> WTAP_ENCAP_PPP
    10:  6,   # FDDI_BITSWAPPED -> WTAP_ENCAP_FDDI_BITSWAPPED
    32:  69,  # REDBACK
    50:  4,   # PPP
    99:  61,  # SYMANTEC
    100: 10,  # ATM_RFC1483
    101: 7,   # RAW_IP
    104: 28,  # CHDLC
    105: 20,  # IEEE_802_11
    106: 11,  # LINUX_ATM_CLIP
    107: 26,  # FRELAY
    108: 174, # LOOP (OpenBSD loopback, network-byte-order AF_)
    109: 38,  # ENC
    113: 25,  # SLL (Linux cooked v1)
    114: 30,  # LOCALTALK
    117: 39,  # PFLOG
    118: 29,  # CISCO_IOS
    119: 21,  # IEEE_802_11_PRISM
    121: 32,  # HHDLC
    122: 18,  # IP_OVER_FC
    123: 13,  # ATM_PDUS (SunATM)
    127: 23,  # IEEE_802_11_RADIOTAP
    128: 37,  # TZSP
    129: 9,   # ARCNET_LINUX
    139: 75,  # MTP2_WITH_PHDR
    140: 42,  # MTP2
    141: 43,  # MTP3
    143: 33,  # DOCSIS -> WTAP_ENCAP_DOCSIS
    144: 44,  # IRDA
    147: 45,  # USER0
    148: 46,  # USER1
    149: 47,  # USER2
    150: 48,  # USER3
    151: 49,  # USER4
    152: 50,  # USER5
    153: 51,  # USER6
    154: 52,  # USER7
    155: 53,  # USER8
    156: 54,  # USER9
    157: 55,  # USER10
    158: 56,  # USER11
    159: 57,  # USER12
    160: 58,  # USER13
    161: 59,  # USER14
    162: 60,  # USER15
    163: 24,  # IEEE_802_11_AVS
    165: 63,  # BACNET_MS_TP -> WTAP_ENCAP_BACNET_MS_TP
    169: 66,  # GPRS_LLC
    187: 41,  # BLUETOOTH_H4
    189: 95,  # USB_LINUX
    192: 97,  # PPI
    195: 104, # IEEE802_15_4
    197: 98,  # ERF
    201: 99,  # BLUETOOTH_H4_WITH_PHDR
    203: 131, # LAPD
    204: 19,  # PPP_WITH_PHDR
    227: 125, # SOCKETCAN
    228: 129, # RAW_IP4
    229: 130, # RAW_IP6
    231: 146, # DBUS -> WTAP_ENCAP_DBUS
    248: 149, # SCTP
    251: 154, # BLUETOOTH_LE_LL
    253: 158, # NETLINK
    276: 210, # SLL2
}
# fmt: on


def dlt_to_wtap(dlt: int) -> int:
    """Convert a pcap DLT link-layer type to a Wireshark WTAP encap ID.

    Returns the DLT unchanged if no mapping is known (best-effort fallback).
    """
    return _DLT_TO_WTAP.get(dlt, dlt)


@dataclass
class CorpusStats:
    total_packets: int = 0
    matched_packets: int = 0
    unique_packets: int = 0
    skipped_packets: int = 0
    files_processed: int = 0
    encap_distribution: Dict[int, int] = field(default_factory=dict)


def extract_by_encap(
    pcap_paths: List[Path],
    target_encap: EncapType,
    output_dir: Path,
    console: Console = None,
) -> CorpusStats:
    """Extract raw packet payloads matching a specific encap type from PCAPs.

    Parses pcap/pcapng files, filters by link-layer type, extracts raw
    packet bytes (no pcap headers), and deduplicates by SHA-256.

    Args:
        pcap_paths: List of pcap/pcapng file paths.
        target_encap: Target encapsulation type to filter by.
        output_dir: Directory to write raw payload files.
        console: Rich console for progress output.

    Returns:
        CorpusStats with extraction statistics.
    """
    console = console or Console()
    output_dir.mkdir(parents=True, exist_ok=True)

    stats = CorpusStats()
    seen_hashes: Set[str] = set()

    with Progress(console=console) as progress:
        task = progress.add_task(
            f"Extracting encap={target_encap.name} packets...",
            total=len(pcap_paths),
        )

        for pcap_path in pcap_paths:
            stats.files_processed += 1
            try:
                data = pcap_path.read_bytes()
            except (OSError, IOError):
                stats.skipped_packets += 1
                progress.advance(task)
                continue

            payloads = _extract_payloads(data, target_encap.id, stats)

            for payload in payloads:
                if len(payload) == 0:
                    continue

                h = hashlib.sha256(payload).hexdigest()
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)

                stats.unique_packets += 1
                out_path = output_dir / f"pkt_{h[:16]}.raw"
                out_path.write_bytes(payload)

            progress.advance(task)

    return stats


def _extract_payloads(
    data: bytes, target_encap_id: int, stats: CorpusStats
) -> List[bytes]:
    """Extract raw packet payloads from pcap/pcapng binary data."""
    if len(data) < 4:
        return []

    magic = struct.unpack("<I", data[:4])[0]

    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        return _extract_pcap_payloads(data, "<", target_encap_id, stats)
    elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
        return _extract_pcap_payloads(data, ">", target_encap_id, stats)
    elif magic == PCAPNG_SHB:
        return _extract_pcapng_payloads(data, target_encap_id, stats)

    return []


def _extract_pcap_payloads(
    data: bytes, endian: str, target_encap_id: int, stats: CorpusStats
) -> List[bytes]:
    """Extract payloads from a classic pcap file."""
    if len(data) < 24:
        return []

    # Global header: 24 bytes
    # network (link-layer type) is at offset 20, 4 bytes
    link_type_dlt = struct.unpack(f"{endian}I", data[20:24])[0]
    link_type = dlt_to_wtap(link_type_dlt)

    # Track encap distribution (by WTAP ID)
    stats.encap_distribution[link_type] = stats.encap_distribution.get(link_type, 0)

    # If link type doesn't match, skip entire file
    if link_type != target_encap_id:
        # Count all packets as skipped
        offset = 24
        while offset + 16 <= len(data):
            incl_len = struct.unpack(f"{endian}I", data[offset + 8:offset + 12])[0]
            stats.total_packets += 1
            stats.skipped_packets += 1
            stats.encap_distribution[link_type] += 1
            offset += 16 + incl_len
        return []

    # Extract each packet's raw payload
    payloads = []
    offset = 24
    while offset + 16 <= len(data):
        incl_len = struct.unpack(f"{endian}I", data[offset + 8:offset + 12])[0]
        stats.total_packets += 1
        stats.encap_distribution[link_type] += 1

        payload_start = offset + 16
        payload_end = payload_start + incl_len

        if payload_end > len(data):
            break

        payload = data[payload_start:payload_end]
        payloads.append(payload)
        stats.matched_packets += 1

        offset = payload_end

    return payloads


def _extract_pcapng_payloads(
    data: bytes, target_encap_id: int, stats: CorpusStats
) -> List[bytes]:
    """Extract payloads from a pcapng file, filtering by interface link type."""
    interface_link_types: Dict[int, int] = {}  # interface_id -> link_type
    payloads = []

    offset = 0
    while offset + 8 <= len(data):
        block_type = struct.unpack("<I", data[offset:offset + 4])[0]
        block_len = struct.unpack("<I", data[offset + 4:offset + 8])[0]

        if block_len < 12 or offset + block_len > len(data):
            break

        # Interface Description Block
        if block_type == PCAPNG_IDB:
            if block_len >= 20:
                link_type_dlt = struct.unpack("<H", data[offset + 8:offset + 10])[0]
                link_type = dlt_to_wtap(link_type_dlt)
                iface_id = len(interface_link_types)
                interface_link_types[iface_id] = link_type

        # Enhanced Packet Block
        elif block_type == PCAPNG_EPB:
            if block_len >= 32:
                iface_id = struct.unpack("<I", data[offset + 8:offset + 12])[0]
                cap_len = struct.unpack("<I", data[offset + 20:offset + 24])[0]
                stats.total_packets += 1

                link_type = interface_link_types.get(iface_id, -1)
                stats.encap_distribution[link_type] = \
                    stats.encap_distribution.get(link_type, 0) + 1

                if link_type == target_encap_id:
                    payload_start = offset + 28
                    payload_end = payload_start + cap_len
                    if payload_end <= offset + block_len:
                        payloads.append(data[payload_start:payload_end])
                        stats.matched_packets += 1
                else:
                    stats.skipped_packets += 1

        # Simple Packet Block
        elif block_type == PCAPNG_SPB:
            if block_len >= 16:
                orig_len = struct.unpack("<I", data[offset + 8:offset + 12])[0]
                cap_len = min(orig_len, block_len - 16)
                stats.total_packets += 1

                # SPB uses interface 0
                link_type = interface_link_types.get(0, -1)
                stats.encap_distribution[link_type] = \
                    stats.encap_distribution.get(link_type, 0) + 1

                if link_type == target_encap_id:
                    payload_start = offset + 12
                    payload_end = payload_start + cap_len
                    if payload_end <= offset + block_len:
                        payloads.append(data[payload_start:payload_end])
                        stats.matched_packets += 1
                else:
                    stats.skipped_packets += 1

        # Advance to next block (4-byte aligned)
        offset += block_len
        if offset % 4 != 0:
            offset += 4 - (offset % 4)

    return payloads


def find_pcap_files(path: Path) -> List[Path]:
    """Recursively find pcap/pcapng/cap files in a directory or return single file."""
    if path.is_file():
        return [path]

    extensions = {".pcap", ".pcapng", ".cap"}
    files = []
    for f in sorted(path.rglob("*")):
        if f.is_file() and f.suffix.lower() in extensions:
            files.append(f)
    return files


def probe_encaps(pcap_paths: List[Path], max_packets: int = 1000) -> Dict[int, int]:
    """Probe a list of PCAPs and return encap distribution from the first N packets.

    Returns a dict of {wtap_encap_id: packet_count}, sorted by count descending.
    Stops after max_packets total packets have been seen across all files.
    """
    distribution: Dict[int, int] = {}
    total = 0

    for pcap_path in pcap_paths:
        if total >= max_packets:
            break
        try:
            data = pcap_path.read_bytes()
        except (OSError, IOError):
            continue

        if len(data) < 4:
            continue

        magic = struct.unpack("<I", data[:4])[0]

        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            endian = "<"
        elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
            endian = ">"
        elif magic == PCAPNG_SHB:
            endian = None
        else:
            continue

        if endian is not None:
            # Classic pcap: all packets share one link type
            if len(data) < 24:
                continue
            link_type = dlt_to_wtap(struct.unpack(f"{endian}I", data[20:24])[0])
            offset = 24
            while offset + 16 <= len(data) and total < max_packets:
                incl_len = struct.unpack(f"{endian}I", data[offset + 8:offset + 12])[0]
                distribution[link_type] = distribution.get(link_type, 0) + 1
                total += 1
                offset += 16 + incl_len
        else:
            # pcapng: per-interface link types
            iface_types: Dict[int, int] = {}
            offset = 0
            while offset + 8 <= len(data) and total < max_packets:
                block_type = struct.unpack("<I", data[offset:offset + 4])[0]
                block_len = struct.unpack("<I", data[offset + 4:offset + 8])[0]
                if block_len < 12 or offset + block_len > len(data):
                    break
                if block_type == PCAPNG_IDB and block_len >= 20:
                    dlt = struct.unpack("<H", data[offset + 8:offset + 10])[0]
                    iface_types[len(iface_types)] = dlt_to_wtap(dlt)
                elif block_type == PCAPNG_EPB and block_len >= 32:
                    iface_id = struct.unpack("<I", data[offset + 8:offset + 12])[0]
                    link_type = iface_types.get(iface_id, -1)
                    distribution[link_type] = distribution.get(link_type, 0) + 1
                    total += 1
                elif block_type == PCAPNG_SPB and block_len >= 16:
                    link_type = iface_types.get(0, -1)
                    distribution[link_type] = distribution.get(link_type, 0) + 1
                    total += 1
                offset += block_len
                if offset % 4 != 0:
                    offset += 4 - (offset % 4)

    return dict(sorted(distribution.items(), key=lambda x: -x[1]))


def write_pcapng(packets: List[bytes], wtap_encap_id: int, output_path: Path) -> int:
    """Write a list of raw packet payloads into a pcapng file.

    Uses the WTAP encap ID to look up the corresponding DLT for the
    Interface Description Block. Returns the number of packets written.
    """
    # Reverse-map WTAP -> DLT for the IDB link type field.
    # Fall back to the WTAP ID itself if no mapping exists.
    dlt = {v: k for k, v in _DLT_TO_WTAP.items()}.get(wtap_encap_id, wtap_encap_id)

    def _pad4(n: int) -> int:
        return (n + 3) & ~3

    def _block(block_type: int, body: bytes) -> bytes:
        # block_type (4) + total_length (4) + body + total_length (4)
        total = 12 + len(body)
        pad = _pad4(total) - total
        total_padded = total + pad
        hdr = struct.pack("<II", block_type, total_padded)
        return hdr + body + b"\x00" * pad + struct.pack("<I", total_padded)

    # Section Header Block (type 0x0A0D0D0A is special — no _block wrapper)
    def _shb() -> bytes:
        body = struct.pack("<IHH", 0x1A2B3C4D, 1, 0)  # byte-order magic, maj, min
        body += struct.pack("<q", -1)                   # section length unknown
        total = 12 + len(body)
        return struct.pack("<II", PCAPNG_SHB, total) + body + struct.pack("<I", total)

    # Interface Description Block
    def _idb(link_type: int) -> bytes:
        body = struct.pack("<HHI", link_type, 0, 65535)  # link_type, reserved, snaplen
        return _block(PCAPNG_IDB, body)

    # Enhanced Packet Block
    def _epb(data: bytes) -> bytes:
        cap_len = len(data)
        pad = _pad4(cap_len) - cap_len
        body = struct.pack("<IIIII",
            0,          # interface_id
            0, 0,       # timestamp high, low
            cap_len,    # captured length
            cap_len,    # original length
        )
        body += data + b"\x00" * pad
        return _block(PCAPNG_EPB, body)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(_shb())
        f.write(_idb(dlt))
        for pkt in packets:
            f.write(_epb(pkt))

    return len(packets)
