"""Encapsulation type registry and interactive picker.

Maps WTAP_ENCAP_* values from wiretap/wtap.h to human-readable names.
"""

import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.table import Table


def _build_wtap_to_dlt() -> Dict[int, int]:
    """Build a reverse mapping from WTAP encap ID to DLT number.

    Imported lazily from corpus to avoid circular imports.
    Only the first DLT for each WTAP ID is kept (some WTAP IDs map from
    multiple DLTs, e.g. WTAP_ENCAP_PPP comes from DLT 9 and 50).
    """
    from wirefuzz.corpus import _DLT_TO_WTAP
    result: Dict[int, int] = {}
    for dlt, wtap in _DLT_TO_WTAP.items():
        if wtap not in result:
            result[wtap] = dlt
    return result

@dataclass
class EncapType:
    id: int
    name: str
    full_name: str


# Complete registry from wiretap/wtap.h WTAP_ENCAP_* defines.
# fmt: off
ENCAP_REGISTRY: Dict[int, EncapType] = {e.id: e for e in [
    EncapType(-2, "NONE", "No link-layer encapsulation"),
    EncapType(-1, "PER_PACKET", "Per-packet encapsulation"),
    EncapType(0,  "UNKNOWN", "Unknown"),
    EncapType(1,  "ETHERNET", "Ethernet"),
    EncapType(2,  "TOKEN_RING", "Token Ring"),
    EncapType(3,  "SLIP", "SLIP"),
    EncapType(4,  "PPP", "PPP"),
    EncapType(5,  "FDDI", "FDDI"),
    EncapType(6,  "FDDI_BITSWAPPED", "FDDI (bitswapped)"),
    EncapType(7,  "RAW_IP", "Raw IP"),
    EncapType(8,  "ARCNET", "ARCNET"),
    EncapType(9,  "ARCNET_LINUX", "ARCNET (Linux)"),
    EncapType(10, "ATM_RFC1483", "ATM RFC 1483"),
    EncapType(11, "LINUX_ATM_CLIP", "Linux ATM CLIP"),
    EncapType(12, "LAPB", "LAPB"),
    EncapType(13, "ATM_PDUS", "ATM PDUs"),
    EncapType(14, "ATM_PDUS_UNTRUNCATED", "ATM PDUs (untruncated)"),
    EncapType(15, "NULL", "NULL/Loopback"),
    EncapType(16, "ASCEND", "Ascend"),
    EncapType(17, "ISDN", "ISDN"),
    EncapType(18, "IP_OVER_FC", "IP over Fibre Channel"),
    EncapType(19, "PPP_WITH_PHDR", "PPP with pseudo-header"),
    EncapType(20, "IEEE_802_11", "IEEE 802.11 Wireless LAN"),
    EncapType(21, "IEEE_802_11_PRISM", "IEEE 802.11 (Prism header)"),
    EncapType(22, "IEEE_802_11_WITH_RADIO", "IEEE 802.11 (with radio info)"),
    EncapType(23, "IEEE_802_11_RADIOTAP", "IEEE 802.11 (Radiotap header)"),
    EncapType(24, "IEEE_802_11_AVS", "IEEE 802.11 (AVS header)"),
    EncapType(25, "SLL", "Linux cooked-mode capture (SLL)"),
    EncapType(26, "FRELAY", "Frame Relay"),
    EncapType(27, "FRELAY_WITH_PHDR", "Frame Relay (with PHDR)"),
    EncapType(28, "CHDLC", "Cisco HDLC"),
    EncapType(29, "CISCO_IOS", "Cisco IOS"),
    EncapType(30, "LOCALTALK", "LocalTalk"),
    EncapType(31, "OLD_PFLOG", "OpenBSD PF log (old)"),
    EncapType(32, "HHDLC", "HiPath HDLC"),
    EncapType(33, "DOCSIS", "DOCSIS"),
    EncapType(34, "COSINE", "CoSine L2"),
    EncapType(35, "WFLEET_HDLC", "Wellfleet HDLC"),
    EncapType(36, "SDLC", "SDLC"),
    EncapType(37, "TZSP", "TZSP"),
    EncapType(38, "ENC", "OpenBSD enc(4)"),
    EncapType(39, "PFLOG", "OpenBSD PF log"),
    EncapType(40, "CHDLC_WITH_PHDR", "Cisco HDLC (with PHDR)"),
    EncapType(41, "BLUETOOTH_H4", "Bluetooth H4"),
    EncapType(42, "MTP2", "MTP2"),
    EncapType(43, "MTP3", "MTP3"),
    EncapType(44, "IRDA", "IrDA"),
    EncapType(45, "USER0", "User DLT 0"),
    EncapType(46, "USER1", "User DLT 1"),
    EncapType(47, "USER2", "User DLT 2"),
    EncapType(48, "USER3", "User DLT 3"),
    EncapType(49, "USER4", "User DLT 4"),
    EncapType(50, "USER5", "User DLT 5"),
    EncapType(51, "USER6", "User DLT 6"),
    EncapType(52, "USER7", "User DLT 7"),
    EncapType(53, "USER8", "User DLT 8"),
    EncapType(54, "USER9", "User DLT 9"),
    EncapType(55, "USER10", "User DLT 10"),
    EncapType(56, "USER11", "User DLT 11"),
    EncapType(57, "USER12", "User DLT 12"),
    EncapType(58, "USER13", "User DLT 13"),
    EncapType(59, "USER14", "User DLT 14"),
    EncapType(60, "USER15", "User DLT 15"),
    EncapType(61, "SYMANTEC", "Symantec Enterprise Firewall"),
    EncapType(62, "APPLE_IP_OVER_IEEE1394", "Apple IP over IEEE 1394"),
    EncapType(63, "BACNET_MS_TP", "BACnet MS/TP"),
    EncapType(64, "NETTL_RAW_ICMP", "HP-UX nettl Raw ICMP"),
    EncapType(65, "NETTL_RAW_ICMPV6", "HP-UX nettl Raw ICMPv6"),
    EncapType(66, "GPRS_LLC", "GPRS LLC"),
    EncapType(67, "JUNIPER_ATM1", "Juniper ATM1"),
    EncapType(68, "JUNIPER_ATM2", "Juniper ATM2"),
    EncapType(69, "REDBACK", "Redback SmartEdge"),
    EncapType(70, "NETTL_RAW_IP", "HP-UX nettl Raw IP"),
    EncapType(71, "NETTL_ETHERNET", "HP-UX nettl Ethernet"),
    EncapType(72, "NETTL_TOKEN_RING", "HP-UX nettl Token Ring"),
    EncapType(73, "NETTL_FDDI", "HP-UX nettl FDDI"),
    EncapType(74, "NETTL_UNKNOWN", "HP-UX nettl Unknown"),
    EncapType(75, "MTP2_WITH_PHDR", "MTP2 with pseudo-header"),
    EncapType(76, "JUNIPER_PPPOE", "Juniper PPPoE"),
    EncapType(77, "GCOM_TIE1", "GCOM TIE1"),
    EncapType(78, "GCOM_SERIAL", "GCOM Serial"),
    EncapType(79, "NETTL_X25", "HP-UX nettl X.25"),
    EncapType(80, "K12", "K12 protocol analyzer"),
    EncapType(81, "JUNIPER_MLPPP", "Juniper MLPPP"),
    EncapType(82, "JUNIPER_MLFR", "Juniper MLFR"),
    EncapType(83, "JUNIPER_ETHER", "Juniper Ethernet"),
    EncapType(84, "JUNIPER_PPP", "Juniper PPP"),
    EncapType(85, "JUNIPER_FRELAY", "Juniper Frame Relay"),
    EncapType(86, "JUNIPER_CHDLC", "Juniper C-HDLC"),
    EncapType(87, "JUNIPER_GGSN", "Juniper GGSN"),
    EncapType(88, "LINUX_LAPD", "Linux LAPD"),
    EncapType(89, "CATAPULT_DCT2000", "Catapult DCT2000"),
    EncapType(90, "BER", "ASN.1 BER"),
    EncapType(91, "JUNIPER_VP", "Juniper Voice PIC"),
    EncapType(92, "USB_FREEBSD", "USB (FreeBSD)"),
    EncapType(93, "IEEE802_16_MAC_CPS", "IEEE 802.16 MAC CPS"),
    EncapType(94, "NETTL_RAW_TELNET", "HP-UX nettl Raw Telnet"),
    EncapType(95, "USB_LINUX", "USB (Linux)"),
    EncapType(96, "MPEG", "MPEG"),
    EncapType(97, "PPI", "Per-Packet Information"),
    EncapType(98, "ERF", "Endace ERF"),
    EncapType(99, "BLUETOOTH_H4_WITH_PHDR", "Bluetooth H4 (with PHDR)"),
    EncapType(100, "SITA", "SITA"),
    EncapType(101, "SCCP", "SCCP"),
    EncapType(102, "BLUETOOTH_HCI", "Bluetooth HCI"),
    EncapType(103, "IPMB_KONTRON", "IPMB (Kontron)"),
    EncapType(104, "IEEE802_15_4", "IEEE 802.15.4"),
    EncapType(105, "X2E_XORAYA", "X2E Xoraya"),
    EncapType(106, "FLEXRAY", "FlexRay"),
    EncapType(107, "LIN", "LIN"),
    EncapType(108, "MOST", "MOST"),
    EncapType(109, "CAN20B", "CAN 2.0B"),
    EncapType(110, "LAYER1_EVENT", "Layer 1 Event"),
    EncapType(111, "X2E_SERIAL", "X2E Serial"),
    EncapType(112, "I2C_LINUX", "I2C (Linux)"),
    EncapType(113, "IEEE802_15_4_NONASK_PHY", "IEEE 802.15.4 (non-ASK PHY)"),
    EncapType(114, "TNEF", "TNEF"),
    EncapType(115, "USB_LINUX_MMAPPED", "USB (Linux mmapped)"),
    EncapType(116, "GSM_UM", "GSM Um"),
    EncapType(117, "DPNSS", "DPNSS"),
    EncapType(118, "PACKETLOGGER", "PacketLogger"),
    EncapType(119, "NSTRACE_1_0", "NetScaler 1.0"),
    EncapType(120, "NSTRACE_2_0", "NetScaler 2.0"),
    EncapType(121, "FIBRE_CHANNEL_FC2", "Fibre Channel FC-2"),
    EncapType(122, "FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS", "Fibre Channel FC-2 (with delimiters)"),
    EncapType(123, "JPEG_JFIF", "JPEG/JFIF"),
    EncapType(124, "IPNET", "Solaris ipnet"),
    EncapType(125, "SOCKETCAN", "SocketCAN"),
    EncapType(126, "IEEE_802_11_NETMON", "IEEE 802.11 (NetMon)"),
    EncapType(127, "IEEE802_15_4_NOFCS", "IEEE 802.15.4 (no FCS)"),
    EncapType(128, "RAW_IPFIX", "Raw IPFIX"),
    EncapType(129, "RAW_IP4", "Raw IPv4"),
    EncapType(130, "RAW_IP6", "Raw IPv6"),
    EncapType(131, "LAPD", "LAPD"),
    EncapType(132, "DVBCI", "DVB-CI"),
    EncapType(133, "MUX27010", "MUX27010"),
    EncapType(134, "MIME", "MIME"),
    EncapType(135, "NETANALYZER", "Hilscher netANALYZER"),
    EncapType(136, "NETANALYZER_TRANSPARENT", "Hilscher netANALYZER (transparent)"),
    EncapType(137, "IP_OVER_IB_SNOOP", "IP over InfiniBand (Snoop)"),
    EncapType(138, "MPEG_2_TS", "MPEG-2 Transport Stream"),
    EncapType(139, "PPP_ETHER", "PPP over Ethernet"),
    EncapType(140, "NFC_LLCP", "NFC LLCP"),
    EncapType(141, "NFLOG", "NFLOG"),
    EncapType(142, "V5_EF", "V5 Envelope Function"),
    EncapType(143, "BACNET_MS_TP_WITH_PHDR", "BACnet MS/TP (with PHDR)"),
    EncapType(144, "IXVERIWAVE", "IxVeriWave"),
    EncapType(145, "SDH", "SDH"),
    EncapType(146, "DBUS", "D-Bus"),
    EncapType(147, "AX25_KISS", "AX.25 (KISS)"),
    EncapType(148, "AX25", "AX.25"),
    EncapType(149, "SCTP", "SCTP"),
    EncapType(150, "INFINIBAND", "InfiniBand"),
    EncapType(151, "JUNIPER_SVCS", "Juniper Services"),
    EncapType(152, "USBPCAP", "USBPcap"),
    EncapType(153, "RTAC_SERIAL", "RTAC Serial"),
    EncapType(154, "BLUETOOTH_LE_LL", "Bluetooth Low Energy Link Layer"),
    EncapType(155, "WIRESHARK_UPPER_PDU", "Wireshark Upper PDU"),
    EncapType(156, "STANAG_4607", "STANAG 4607"),
    EncapType(157, "STANAG_5066_D_PDU", "STANAG 5066 D_PDU"),
    EncapType(158, "NETLINK", "Linux Netlink"),
    EncapType(159, "BLUETOOTH_LINUX_MONITOR", "Bluetooth Linux Monitor"),
    EncapType(160, "BLUETOOTH_BREDR_BB", "Bluetooth BR/EDR Baseband"),
    EncapType(161, "BLUETOOTH_LE_LL_WITH_PHDR", "Bluetooth LE LL (with PHDR)"),
    EncapType(162, "NSTRACE_3_0", "NetScaler 3.0"),
    EncapType(163, "LOGCAT", "Android Logcat"),
    EncapType(164, "LOGCAT_BRIEF", "Android Logcat Brief"),
    EncapType(165, "LOGCAT_PROCESS", "Android Logcat Process"),
    EncapType(166, "LOGCAT_TAG", "Android Logcat Tag"),
    EncapType(167, "LOGCAT_THREAD", "Android Logcat Thread"),
    EncapType(168, "LOGCAT_TIME", "Android Logcat Time"),
    EncapType(169, "LOGCAT_THREADTIME", "Android Logcat Threadtime"),
    EncapType(170, "LOGCAT_LONG", "Android Logcat Long"),
    EncapType(171, "PKTAP", "Apple PKTAP"),
    EncapType(172, "EPON", "EPON"),
    EncapType(173, "IPMI_TRACE", "IPMI Trace"),
    EncapType(174, "LOOP", "OpenBSD Loopback"),
    EncapType(175, "JSON", "JSON"),
    EncapType(176, "NSTRACE_3_5", "NetScaler 3.5"),
    EncapType(177, "ISO14443", "ISO 14443 contactless smartcard"),
    EncapType(178, "GFP_T", "ITU-T G.7041 GFP-T"),
    EncapType(179, "GFP_F", "ITU-T G.7041 GFP-F"),
    EncapType(180, "IP_OVER_IB_PCAP", "IP over InfiniBand (pcap)"),
    EncapType(181, "JUNIPER_VN", "Juniper VN"),
    EncapType(182, "USB_DARWIN", "USB (macOS)"),
    EncapType(183, "LORATAP", "LoRaTap"),
    EncapType(184, "3MB_ETHERNET", "3Mb Ethernet"),
    EncapType(185, "VSOCK", "Linux vsock"),
    EncapType(186, "NORDIC_BLE", "Nordic BLE Sniffer"),
    EncapType(187, "NETMON_NET_NETEVENT", "NetMon Network Event"),
    EncapType(188, "NETMON_HEADER", "NetMon Header"),
    EncapType(189, "NETMON_NET_FILTER", "NetMon Network Filter"),
    EncapType(190, "NETMON_NETWORK_INFO_EX", "NetMon Network Info"),
    EncapType(191, "MA_WFP_CAPTURE_V4", "Message Analyzer WFP Capture v4"),
    EncapType(192, "MA_WFP_CAPTURE_V6", "Message Analyzer WFP Capture v6"),
    EncapType(193, "MA_WFP_CAPTURE_2V4", "Message Analyzer WFP Capture 2v4"),
    EncapType(194, "MA_WFP_CAPTURE_2V6", "Message Analyzer WFP Capture 2v6"),
    EncapType(195, "MA_WFP_CAPTURE_AUTH_V4", "Message Analyzer WFP Auth v4"),
    EncapType(196, "MA_WFP_CAPTURE_AUTH_V6", "Message Analyzer WFP Auth v6"),
    EncapType(197, "JUNIPER_ST", "Juniper Secure Tunnel"),
    EncapType(198, "ETHERNET_MPACKET", "Ethernet mPacket"),
    EncapType(199, "DOCSIS31_XRA31", "DOCSIS 3.1 XRA-31"),
    EncapType(200, "DPAUXMON", "DisplayPort AUX channel"),
    EncapType(201, "RUBY_MARSHAL", "Ruby Marshal"),
    EncapType(202, "RFC7468", "RFC 7468 (PEM)"),
    EncapType(203, "SYSTEMD_JOURNAL", "systemd Journal"),
    EncapType(204, "EBHSCR", "EBHSCR"),
    EncapType(205, "VPP", "VPP graph dispatch trace"),
    EncapType(206, "IEEE802_15_4_TAP", "IEEE 802.15.4 TAP"),
    EncapType(207, "LOG_3GPP", "3GPP Log"),
    EncapType(208, "USB_2_0", "USB 2.0"),
    EncapType(209, "MP4", "MP4"),
    EncapType(210, "SLL2", "Linux cooked-mode capture v2 (SLL2)"),
    EncapType(211, "ZWAVE_SERIAL", "Z-Wave Serial"),
    EncapType(212, "ETW", "Event Tracing for Windows"),
    EncapType(213, "ERI_ENB_LOG", "Ericsson eNB Log"),
    EncapType(214, "ZBNCP", "ZBNCP"),
    EncapType(215, "USB_2_0_LOW_SPEED", "USB 2.0 (Low Speed)"),
    EncapType(216, "USB_2_0_FULL_SPEED", "USB 2.0 (Full Speed)"),
    EncapType(217, "USB_2_0_HIGH_SPEED", "USB 2.0 (High Speed)"),
    EncapType(218, "AUTOSAR_DLT", "AUTOSAR DLT"),
    EncapType(219, "AUERSWALD_LOG", "Auerswald Log"),
    EncapType(220, "ATSC_ALP", "ATSC ALP"),
    EncapType(221, "FIRA_UCI", "FiRa UCI"),
    EncapType(222, "SILABS_DEBUG_CHANNEL", "Silicon Labs Debug Channel"),
    EncapType(223, "MDB", "MDB"),
    EncapType(224, "EMS", "EMS"),
    EncapType(225, "DECT_NR", "DECT NR"),
    EncapType(226, "MMODULE", "mModule"),
    EncapType(227, "PROCMON", "Process Monitor"),
]}
# fmt: on

# Most commonly fuzzed encap types - shown first in interactive picker
COMMON_ENCAP_IDS = [
    1,    # Ethernet
    7,    # Raw IP
    129,  # Raw IPv4
    130,  # Raw IPv6
    25,   # SLL (Linux cooked)
    210,  # SLL2
    15,   # NULL/Loopback
    20,   # IEEE 802.11
    23,   # IEEE 802.11 Radiotap
    4,    # PPP
    104,  # IEEE 802.15.4
    125,  # SocketCAN
    33,   # DOCSIS
    41,   # Bluetooth H4
    154,  # Bluetooth LE LL
    95,   # USB Linux
    152,  # USBPcap
    158,  # Netlink
    149,  # SCTP
    139,  # PPP over Ethernet
    141,  # NFLOG
    90,   # BER
    134,  # MIME
    175,  # JSON
]


def get_encap(id_or_name: str) -> Optional[EncapType]:
    """Look up an encap type by ID (int) or name (string).

    Accepts: "1", "ETHERNET", "ethernet", "IEEE_802_11", etc.
    Returns None if not found.
    """
    # Try as integer ID
    try:
        encap_id = int(id_or_name)
        return ENCAP_REGISTRY.get(encap_id)
    except ValueError:
        pass

    # Try as name (case-insensitive)
    name_upper = id_or_name.upper().strip()
    for encap in ENCAP_REGISTRY.values():
        if encap.name == name_upper:
            return encap

    return None


def list_encaps(common_only: bool = False) -> List[EncapType]:
    """Return list of encap types, optionally filtered to common ones."""
    if common_only:
        return [ENCAP_REGISTRY[eid] for eid in COMMON_ENCAP_IDS
                if eid in ENCAP_REGISTRY]
    return sorted(ENCAP_REGISTRY.values(), key=lambda e: e.id)


def display_encaps(common_only: bool = False, console: Console = None):
    """Display encap types as a rich table."""
    console = console or Console()
    encaps = list_encaps(common_only=common_only)
    wtap_to_dlt = _build_wtap_to_dlt()

    title = "Common Encapsulation Types" if common_only else "All Encapsulation Types"
    table = Table(title=title, show_lines=False)
    table.add_column("WTAP", style="bold cyan", justify="right", width=5)
    table.add_column("DLT", style="dim", justify="right", width=5)
    table.add_column("Name", style="bold", width=36)
    table.add_column("Description", style="dim")

    for e in encaps:
        dlt = wtap_to_dlt.get(e.id)
        dlt_str = str(dlt) if dlt is not None else "—"
        table.add_row(str(e.id), dlt_str, e.name, e.full_name)

    console.print()
    console.print(table)
    console.print()
    console.print(f"  [dim]Total: {len(encaps)} encapsulation types[/dim]")
    console.print()


def pick_encap_interactive(console: Console = None) -> EncapType:
    """Show interactive fuzzy picker for encapsulation type selection.

    Common types are shown first, followed by all others.
    Falls back to numbered list if InquirerPy is not available.
    """
    console = console or Console()

    wtap_to_dlt = _build_wtap_to_dlt()

    def _fmt(e: EncapType) -> str:
        dlt = wtap_to_dlt.get(e.id)
        dlt_str = f"DLT {dlt:>3d}" if dlt is not None else "        "
        return f"WTAP {e.id:>3d}  {dlt_str}  {e.name:<36s} {e.full_name}"

    # Build choices: common first, then the rest
    common_set = set(COMMON_ENCAP_IDS)
    choices = []

    # Common encaps first
    for eid in COMMON_ENCAP_IDS:
        if eid in ENCAP_REGISTRY:
            e = ENCAP_REGISTRY[eid]
            choices.append({"name": _fmt(e), "value": e})

    # All others
    for e in sorted(ENCAP_REGISTRY.values(), key=lambda x: x.id):
        if e.id not in common_set and e.id >= 0:
            choices.append({"name": _fmt(e), "value": e})

    # Non-TTY fallback
    if not sys.stdout.isatty():
        console.print(
            "[yellow]Warning:[/yellow] Non-interactive mode, "
            "defaulting to Ethernet (1)"
        )
        return ENCAP_REGISTRY[1]

    # Interactive selection with InquirerPy
    try:
        from InquirerPy import inquirer

        # Pass choices as dicts (not Choice dataclasses) to avoid InquirerPy
        # calling dataclasses.asdict() which would recursively convert EncapType
        # to a plain dict, losing the type.
        encap = inquirer.fuzzy(
            message="Select encapsulation type:",
            choices=[{"name": c["name"], "value": c["value"]} for c in choices],
            max_height="60%",
        ).execute()

        # Reconstruct EncapType if asdict conversion happened anyway
        if isinstance(encap, dict) and "id" in encap:
            encap = ENCAP_REGISTRY.get(encap["id"], EncapType(**encap))

        return encap

    except ImportError:
        # Fallback: numbered list of common types
        common = list_encaps(common_only=True)
        console.print("\n[bold]Select encapsulation type:[/bold]\n")
        for i, e in enumerate(common, 1):
            dlt = wtap_to_dlt.get(e.id)
            dlt_str = f"DLT {dlt:>3d}" if dlt is not None else "        "
            console.print(f"  {i:3d}) WTAP {e.id:>3d}  {dlt_str}  {e.name:<30s} {e.full_name}")

        console.print(f"\n  [dim]Or enter an encap ID directly (0-227)[/dim]")
        console.print()

        while True:
            try:
                choice = console.input("[bold]Enter number or encap ID:[/bold] ")
                val = int(choice)

                # Check if it's a direct encap ID
                if val in ENCAP_REGISTRY:
                    return ENCAP_REGISTRY[val]

                # Check if it's a list index
                idx = val - 1
                if 0 <= idx < len(common):
                    return common[idx]
            except (ValueError, EOFError):
                pass
            console.print("[red]Invalid choice, try again.[/red]")


# -- PCAP encap type detection --

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D
PCAP_MAGIC_NS_BE = 0x4DC3B2A1
PCAPNG_SHB_MAGIC = 0x0A0D0D0A
PCAPNG_IDB_TYPE = 0x00000001


def _dlt_to_wtap_lookup(dlt: int) -> Optional[EncapType]:
    """Convert a DLT/LINKTYPE value to an EncapType via DLT-to-WTAP mapping.

    pcap/pcapng files store DLT (LINKTYPE) numbers, not WTAP encap IDs.
    """
    from wirefuzz.corpus import dlt_to_wtap
    wtap_id = dlt_to_wtap(dlt)
    return ENCAP_REGISTRY.get(wtap_id)


def get_encap_from_pcap(filepath: Path) -> Optional[EncapType]:
    """Read the link-layer type from a pcap or pcapng file header.

    For pcap: reads the network field from the global header.
    For pcapng: reads the LinkType from the first Interface Description Block.
    Converts DLT/LINKTYPE to WTAP encap ID before lookup.
    Returns None if the format is not recognized.
    """
    try:
        data = filepath.read_bytes()
    except (OSError, IOError):
        return None

    if len(data) < 24:
        return None

    magic = struct.unpack("<I", data[:4])[0]

    # Standard pcap (little-endian)
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        if len(data) < 24:
            return None
        link_type = struct.unpack("<I", data[20:24])[0]
        return _dlt_to_wtap_lookup(link_type)

    # Standard pcap (big-endian)
    if magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
        if len(data) < 24:
            return None
        link_type = struct.unpack(">I", data[20:24])[0]
        return _dlt_to_wtap_lookup(link_type)

    # pcapng: look for Section Header Block + Interface Description Block
    if magic == PCAPNG_SHB_MAGIC:
        return _parse_pcapng_link_type(data)

    return None


def _parse_pcapng_link_type(data: bytes) -> Optional[EncapType]:
    """Parse pcapng to find the first IDB and return its link type."""
    offset = 0
    while offset + 8 <= len(data):
        if len(data) < offset + 8:
            break

        block_type = struct.unpack("<I", data[offset:offset + 4])[0]
        block_len = struct.unpack("<I", data[offset + 4:offset + 8])[0]

        if block_len < 12 or offset + block_len > len(data):
            break

        # Interface Description Block
        if block_type == PCAPNG_IDB_TYPE:
            if block_len >= 20:
                link_type = struct.unpack("<H", data[offset + 8:offset + 10])[0]
                return _dlt_to_wtap_lookup(link_type)

        offset += block_len
        # Ensure 4-byte alignment
        if offset % 4 != 0:
            offset += 4 - (offset % 4)

    return None
