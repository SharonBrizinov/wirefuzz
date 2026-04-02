#!/usr/bin/env python3
"""wirefuzz_campaign.py — Automated full-encap fuzzing campaign.

Iterates over every WTAP encapsulation type (1-227), fuzzes each for a
configurable duration with configurable parallelism, and tracks progress
in a persistent state file so the campaign can be resumed after any
interruption.  Includes a built-in web dashboard for live monitoring.

Usage:
    python wirefuzz_campaign.py /path/to/pcaps -V master
    python wirefuzz_campaign.py /path/to/pcaps -V v4.6.4 --workers 60 --duration 60m
    python wirefuzz_campaign.py /path/to/pcaps --resume  # continue where we left off

Before fuzzing begins, all pcaps are scanned and a state file is written
that records which encap types have seed packets available.  Encap types
with matching seeds are fuzzed first, then the rest are fuzzed with an
empty (synthetic) corpus.
"""

import argparse
import base64
import json
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Rich console (optional graceful fallback)
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# ---------------------------------------------------------------------------
# wirefuzz imports
# ---------------------------------------------------------------------------
from wirefuzz.config import CONFIG
from wirefuzz.corpus import (
    find_pcap_files,
    probe_encaps,
    extract_by_encap,
    CorpusStats,
)
from wirefuzz.docker import build_image, check_docker, image_exists
from wirefuzz.encaps import ENCAP_REGISTRY, EncapType, get_encap
from wirefuzz.fuzzer import start_fuzz_session, FuzzSession

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
STATE_FILENAME = "campaign_state.json"
DEFAULT_DURATION = "60m"
DEFAULT_WORKERS = 60
DEFAULT_OUTPUT = "wirefuzz_runs"
DEFAULT_MAX_SCAN_PACKETS = 350_000
DEFAULT_MAX_EXTRACT_PACKETS = 350_000
SCAN_PACKETS_PER_PCAP = 1000   # packets read per pcap during scan (categorization)

# Encap IDs to skip — they are meta-types, not real dissectors
SKIP_ENCAP_IDS = {-2, -1, 0}  # NONE, PER_PACKET, UNKNOWN

# WTAP encap range: 1-227 (228 real types). IDs beyond 227 don't exist in
# Wireshark's ENCAP_REGISTRY.  DLT numbers go higher (up to 303) but those
# map back to WTAP IDs within this range via dlt_to_wtap().


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------
@dataclass
class EncapState:
    """Tracks the state of a single encap's fuzzing campaign."""
    encap_id: int
    encap_name: str
    status: str = "pending"  # pending | seeded | running | done | failed | skipped
    seed_count: int = 0
    run_dir: str = ""
    crashes: int = 0
    corpus_count: int = 0
    total_execs: int = 0
    coverage: int = 0
    started_at: str = ""
    finished_at: str = ""
    elapsed_secs: int = 0
    error: str = ""


@dataclass
class CampaignState:
    """Persistent campaign state — serialised to JSON between runs."""
    campaign_dir: str = ""
    ws_version: str = "master"
    pcap_dir: str = ""
    workers: int = DEFAULT_WORKERS
    duration: str = DEFAULT_DURATION
    max_len: int = CONFIG.default_max_len
    timeout_ms: int = CONFIG.default_timeout_ms
    rss_limit_mb: int = CONFIG.default_rss_limit_mb
    max_scan_packets: int = DEFAULT_MAX_SCAN_PACKETS
    max_extract_packets: int = DEFAULT_MAX_EXTRACT_PACKETS
    created: str = ""
    updated: str = ""
    # Scan results: wtap_id -> packet count across all pcaps
    encap_scan: Dict[str, int] = field(default_factory=dict)
    pcap_count: int = 0
    total_packets_scanned: int = 0
    # Per-encap state keyed by encap_id (as str for JSON compat)
    encaps: Dict[str, dict] = field(default_factory=dict)

    # ---- persistence helpers ----
    def save(self, path: Path):
        self.updated = datetime.now().isoformat()
        path.write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, path: Path) -> "CampaignState":
        raw = json.loads(path.read_text())
        return cls(**{k: v for k, v in raw.items()
                      if k in cls.__dataclass_fields__})

    def get_encap_state(self, encap_id: int) -> EncapState:
        key = str(encap_id)
        if key not in self.encaps:
            enc = ENCAP_REGISTRY.get(encap_id)
            name = enc.name if enc else f"UNKNOWN_{encap_id}"
            self.encaps[key] = asdict(EncapState(encap_id=encap_id, encap_name=name))
        d = self.encaps[key]
        return EncapState(**{k: v for k, v in d.items()
                            if k in EncapState.__dataclass_fields__})

    def set_encap_state(self, es: EncapState):
        self.encaps[str(es.encap_id)] = asdict(es)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
class CampaignLog:
    """Dual-output logger: Rich console + campaign log file."""

    def __init__(self, log_path: Path, console: Console):
        self.console = console
        self.log_path = log_path
        self._fh = open(log_path, "a", buffering=1)

    def info(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._fh.write(f"[{ts}] {msg}\n")
        self.console.print(f"[cyan][{ts}][/cyan] {msg}")

    def ok(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._fh.write(f"[{ts}] OK: {msg}\n")
        self.console.print(f"[green][{ts}] {msg}[/green]")

    def warn(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._fh.write(f"[{ts}] WARN: {msg}\n")
        self.console.print(f"[yellow][{ts}] {msg}[/yellow]")

    def err(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._fh.write(f"[{ts}] ERROR: {msg}\n")
        self.console.print(f"[bold red][{ts}] {msg}[/bold red]")

    def close(self):
        self._fh.close()


# ---------------------------------------------------------------------------
# Scan phase — build encap distribution from pcaps
# ---------------------------------------------------------------------------
def scan_pcaps(
    pcap_dir: Path,
    state: CampaignState,
    log: CampaignLog,
) -> None:
    """Scan all pcaps, read up to N packets per file, record encap distribution."""
    pcap_files = find_pcap_files(pcap_dir)
    state.pcap_count = len(pcap_files)
    max_total = state.max_scan_packets
    log.info(f"Found {len(pcap_files)} pcap file(s) in {pcap_dir}")
    log.info(f"Max packets to scan: {max_total:,} "
             f"(up to {SCAN_PACKETS_PER_PCAP:,} per file)")

    if not pcap_files:
        log.warn("No pcap files found — all encaps will be fuzzed with synthetic seeds")
        return

    # Aggregate encap distribution across all files
    distribution: Dict[int, int] = {}
    total = 0

    for i, pf in enumerate(pcap_files, 1):
        if total >= max_total:
            log.info(f"  Reached {max_total:,} packet limit, stopping scan")
            break
        if i % 100 == 0 or i == len(pcap_files):
            log.info(f"  Scanned {i}/{len(pcap_files)} files ({total:,} packets so far)")
        remaining = max_total - total
        per_file_limit = min(SCAN_PACKETS_PER_PCAP, remaining)
        per_file = probe_encaps([pf], max_packets=per_file_limit)
        for encap_id, count in per_file.items():
            distribution[encap_id] = distribution.get(encap_id, 0) + count
            total += count

    state.total_packets_scanned = total
    # Store as str keys for JSON
    state.encap_scan = {str(k): v for k, v in
                        sorted(distribution.items(), key=lambda x: -x[1])}

    log.ok(f"Scan complete: {total} packets across {len(distribution)} encap types")

    # Mark encaps that have seeds
    for encap_id_str, count in state.encap_scan.items():
        encap_id = int(encap_id_str)
        if encap_id in SKIP_ENCAP_IDS:
            continue
        es = state.get_encap_state(encap_id)
        es.seed_count = count
        es.status = "seeded" if es.status == "pending" else es.status
        state.set_encap_state(es)


# ---------------------------------------------------------------------------
# Extract corpus for a single encap
# ---------------------------------------------------------------------------
def extract_corpus_for_encap(
    pcap_dir: Path,
    encap: EncapType,
    corpus_dir: Path,
    max_packets: int,
    log: CampaignLog,
) -> int:
    """Extract matching packets from pcaps into corpus_dir.

    Extracts up to max_packets unique packets. Returns actual count written.
    """
    pcap_files = find_pcap_files(pcap_dir)
    if not pcap_files:
        return 0

    corpus_dir.mkdir(parents=True, exist_ok=True)
    stats = extract_by_encap(
        pcap_paths=pcap_files,
        target_encap=encap,
        output_dir=corpus_dir,
        console=Console(quiet=True),  # suppress progress bar
    )

    # Enforce max_packets: if we extracted more, trim the corpus
    written = stats.unique_packets
    if written > max_packets:
        files = sorted(corpus_dir.iterdir())
        for f in files[max_packets:]:
            f.unlink()
        written = max_packets
        log.info(f"  Trimmed corpus to {max_packets:,} packets (had {stats.unique_packets:,})")

    return written


# ---------------------------------------------------------------------------
# Post-run stats collection
# ---------------------------------------------------------------------------
def _collect_post_run_stats(run_dir: Path, es: EncapState):
    """Parse session log and count crash/corpus files after a run."""
    from wirefuzz.monitor import FuzzStats, parse_fuzzer_line

    # Count files
    crashes_dir = run_dir / "crashes"
    if crashes_dir.exists():
        es.crashes = sum(1 for f in crashes_dir.iterdir() if f.is_file())

    corpus_dir = run_dir / "corpus"
    if corpus_dir.exists():
        es.corpus_count = sum(1 for f in corpus_dir.iterdir() if f.is_file())

    # Parse log for execution stats
    log_file = run_dir / "logs" / "session.log"
    if log_file.exists():
        stats = FuzzStats()
        try:
            for line in log_file.read_text().splitlines():
                parse_fuzzer_line(line, stats)
            es.total_execs = stats.total_execs
            es.coverage = stats.coverage
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Fuzz one encap
# ---------------------------------------------------------------------------
def fuzz_encap(
    encap: EncapType,
    state: CampaignState,
    campaign_dir: Path,
    pcap_dir: Optional[Path],
    log: CampaignLog,
    console: Console,
) -> EncapState:
    """Run a single fuzz session for one encap type. Updates state in-place."""
    es = state.get_encap_state(encap.id)
    es.status = "running"
    es.started_at = datetime.now().isoformat()
    state.set_encap_state(es)
    state.save(campaign_dir / STATE_FILENAME)

    # Prepare corpus directory
    corpus_dir = campaign_dir / "corpus_staging" / f"encap_{encap.id}"
    corpus_dir.mkdir(parents=True, exist_ok=True)

    # Extract seeds if we have pcaps and this encap has known seeds
    seed_count = 0
    if pcap_dir and es.seed_count > 0:
        log.info(f"  Extracting seeds for {encap.name} ({es.seed_count} packets available)...")
        seed_count = extract_corpus_for_encap(
            pcap_dir, encap, corpus_dir, state.max_extract_packets, log)
        log.info(f"  Extracted {seed_count} unique seed(s)")

    # Always ensure at least one minimal seed
    if not any(corpus_dir.iterdir()):
        (corpus_dir / "seed_minimal").write_bytes(b"\x00" * 4)
        seed_count = 1

    output_base = Path(state.campaign_dir) / "runs"
    output_base.mkdir(parents=True, exist_ok=True)

    try:
        session = start_fuzz_session(
            version=state.ws_version,
            encap=encap,
            corpus_dir=corpus_dir,
            output_base=output_base,
            workers=state.workers,
            max_len=state.max_len,
            timeout_ms=state.timeout_ms,
            rss_limit_mb=state.rss_limit_mb,
            duration=state.duration,
            pcap_source=pcap_dir,
            samples_before_min=seed_count,
            verbose=False,
            console=console,
        )

        es.run_dir = str(session.run_dir)
        es.status = "done"

        # Gather post-run stats by parsing the session log
        _collect_post_run_stats(session.run_dir, es)

    except KeyboardInterrupt:
        es.status = "done"  # Mark as done on Ctrl+C (duration ran)
        es.finished_at = datetime.now().isoformat()
        state.set_encap_state(es)
        state.save(campaign_dir / STATE_FILENAME)
        raise
    except Exception as exc:
        es.status = "failed"
        es.error = str(exc)[:500]
        log.err(f"  Failed: {exc}")

    es.finished_at = datetime.now().isoformat()
    if es.started_at:
        try:
            dt_start = datetime.fromisoformat(es.started_at)
            dt_end = datetime.fromisoformat(es.finished_at)
            es.elapsed_secs = int((dt_end - dt_start).total_seconds())
        except Exception:
            pass

    state.set_encap_state(es)
    state.save(campaign_dir / STATE_FILENAME)
    return es


# ---------------------------------------------------------------------------
# Progress display
# ---------------------------------------------------------------------------
def print_progress(state: CampaignState, console: Console):
    """Print a rich table summarising campaign progress."""
    table = Table(title="Campaign Progress", show_lines=False, expand=False)
    table.add_column("Status", style="bold", width=10)
    table.add_column("Count", justify="right", width=8)
    table.add_column("Details", width=60)

    counts = {"pending": 0, "seeded": 0, "running": 0,
              "done": 0, "failed": 0, "skipped": 0}
    total_crashes = 0
    crashed_encaps = []

    for _, ed in state.encaps.items():
        s = ed.get("status", "pending")
        counts[s] = counts.get(s, 0) + 1
        cr = ed.get("crashes", 0)
        if cr > 0:
            total_crashes += cr
            crashed_encaps.append(f"{ed.get('encap_name', '?')} ({cr})")

    total = sum(counts.values())
    # Also count encaps not yet in state
    max_id = max((e.id for e in ENCAP_REGISTRY.values() if e.id not in SKIP_ENCAP_IDS), default=0)
    not_started = 0
    for eid in range(0, max_id + 1):
        if eid in SKIP_ENCAP_IDS:
            continue
        if eid not in ENCAP_REGISTRY:
            continue
        if str(eid) not in state.encaps:
            not_started += 1

    counts["pending"] += not_started
    total += not_started

    done = counts["done"] + counts["failed"] + counts["skipped"]

    table.add_row("[green]Done[/green]", str(counts["done"]), "")
    table.add_row("[red]Failed[/red]", str(counts["failed"]), "")
    table.add_row("[yellow]Seeded[/yellow]", str(counts["seeded"]),
                  "Have pcap seeds, waiting to fuzz")
    table.add_row("[dim]Pending[/dim]", str(counts["pending"]),
                  "No seeds, will fuzz with synthetic corpus")
    table.add_row("[cyan]Skipped[/cyan]", str(counts["skipped"]), "")
    table.add_row("", "", "")
    table.add_row("[bold]Total[/bold]", str(total),
                  f"{done}/{total} complete ({100*done//max(total,1)}%)")

    if total_crashes:
        table.add_row("[bold red]Crashes[/bold red]",
                      str(total_crashes),
                      ", ".join(crashed_encaps[:10]))

    console.print()
    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Build the ordered fuzzing queue
# ---------------------------------------------------------------------------
def build_fuzz_queue(
    state: CampaignState,
    encap_range: Optional[Tuple[int, int]] = None,
) -> List[int]:
    """Return list of encap IDs to fuzz, ordered: seeded first, then pending.

    Skips encaps that are already done/failed/skipped/running.
    If encap_range is given, only IDs within [lo, hi] inclusive are considered.
    """
    seeded = []
    pending = []

    max_id = max((e.id for e in ENCAP_REGISTRY.values()), default=0)
    lo = encap_range[0] if encap_range else 0
    hi = encap_range[1] if encap_range else max_id

    for encap_id in range(lo, hi + 1):
        if encap_id in SKIP_ENCAP_IDS:
            continue
        if encap_id not in ENCAP_REGISTRY:
            continue

        es = state.get_encap_state(encap_id)
        if es.status in ("done", "failed", "skipped", "running"):
            continue

        if es.status == "seeded" and es.seed_count > 0:
            seeded.append((encap_id, es.seed_count))
        else:
            pending.append(encap_id)

    # Sort seeded by seed count (most seeds first)
    seeded.sort(key=lambda x: -x[1])

    queue = [eid for eid, _ in seeded] + pending
    return queue


# ---------------------------------------------------------------------------
# Main campaign loop
# ---------------------------------------------------------------------------
def run_campaign(args: argparse.Namespace):
    console = Console()

    campaign_dir = Path(args.output).resolve()
    campaign_dir.mkdir(parents=True, exist_ok=True)
    state_path = campaign_dir / STATE_FILENAME

    log = CampaignLog(campaign_dir / "campaign.log", console)

    # ---- Load or create state ----
    if args.resume and state_path.exists():
        log.info(f"Resuming campaign from {state_path}")
        state = CampaignState.load(state_path)
        # Allow CLI overrides on resume
        if args.workers:
            state.workers = args.workers
        if args.duration:
            state.duration = args.duration
        if args.ws_version:
            state.ws_version = args.ws_version
    else:
        if not args.pcap_dir:
            log.err("--pcap-dir is required for a new campaign (or use --resume)")
            sys.exit(1)
        if not args.ws_version:
            log.err("--version is required for a new campaign")
            sys.exit(1)

        state = CampaignState(
            campaign_dir=str(campaign_dir),
            ws_version=args.ws_version,
            pcap_dir=str(Path(args.pcap_dir).resolve()) if args.pcap_dir else "",
            workers=args.workers or DEFAULT_WORKERS,
            duration=args.duration or DEFAULT_DURATION,
            max_len=args.max_len,
            timeout_ms=args.timeout_ms,
            rss_limit_mb=args.rss_limit_mb,
            max_scan_packets=args.max_scan_packets,
            max_extract_packets=args.max_extract_packets,
            created=datetime.now().isoformat(),
        )

    # ---- Header + full config log ----
    console.print()
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
    console.print("[bold]  wirefuzz campaign — automated full-encap fuzzing[/bold]")
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
    console.print()

    config_lines = [
        ("Wireshark version",  state.ws_version),
        ("Workers per encap",  str(state.workers)),
        ("Duration per encap", state.duration),
        ("Max input length",   f"{state.max_len} bytes"),
        ("Timeout per input",  f"{state.timeout_ms} ms"),
        ("RSS limit",          f"{state.rss_limit_mb} MB"),
        ("Scan packets/pcap",  f"{SCAN_PACKETS_PER_PCAP:,}"),
        ("Max scan packets",   f"{state.max_scan_packets:,} total"),
        ("Max extract packets", f"{state.max_extract_packets:,} per encap"),
        ("Campaign dir",       str(campaign_dir)),
        ("PCAP source",        state.pcap_dir or "(none)"),
        ("Encap range",        args.encap_range or "all (1-227)"),
        ("Resume mode",        "yes" if args.resume else "no"),
        ("Dashboard",          f"http://0.0.0.0:{args.dashboard_port}/" if not args.no_dashboard else "disabled"),
    ]
    for label, value in config_lines:
        padded = f"{label + ':':.<24s}"
        console.print(f"  {padded} {value}")
        log.info(f"  {padded} {value}")

    console.print()

    # ---- Start dashboard ----
    if not args.no_dashboard:
        dash_port = args.dashboard_port
        dash_pw = args.dashboard_password
        try:
            start_dashboard(campaign_dir, port=dash_port, password=dash_pw)
            log.ok(f"Dashboard running at http://0.0.0.0:{dash_port}/ (password: {'***' if dash_pw else 'none'})")
        except Exception as e:
            log.warn(f"Failed to start dashboard: {e}")

    # ---- Docker check ----
    log.info("Checking Docker...")
    try:
        check_docker()
    except Exception as e:
        log.err(f"Docker not available: {e}")
        sys.exit(1)

    # ---- Ensure image is built ----
    if not image_exists(state.ws_version):
        log.info(f"Building Docker image for Wireshark {state.ws_version}...")
        build_image(state.ws_version, console=console)
    else:
        log.ok(f"Docker image exists: {CONFIG.image_tag(state.ws_version)}")

    # ---- Scan phase (only if not yet done) ----
    pcap_dir = Path(state.pcap_dir) if state.pcap_dir else None

    if not state.encap_scan and pcap_dir:
        log.info("=== Phase 1: Scanning pcaps ===")
        scan_pcaps(pcap_dir, state, log)
        state.save(state_path)

        # Show scan results
        console.print()
        scan_table = Table(title="Encap Distribution (from scan)", show_lines=False)
        scan_table.add_column("WTAP ID", justify="right")
        scan_table.add_column("Name")
        scan_table.add_column("Packets", justify="right")
        for eid_str, count in list(state.encap_scan.items())[:30]:
            enc = ENCAP_REGISTRY.get(int(eid_str))
            name = enc.name if enc else f"UNKNOWN_{eid_str}"
            scan_table.add_row(eid_str, name, f"{count:,}")
        if len(state.encap_scan) > 30:
            scan_table.add_row("...", f"({len(state.encap_scan) - 30} more)", "")
        console.print(scan_table)
        console.print()
    elif state.encap_scan:
        n_seeded = sum(1 for v in state.encap_scan.values() if v > 0)
        log.info(f"Scan already done: {state.total_packets_scanned} packets, "
                 f"{n_seeded} encap types with seeds")

    # ---- Initialize all encap states ----
    max_id = max((e.id for e in ENCAP_REGISTRY.values()), default=0)
    for encap_id in range(0, max_id + 1):
        if encap_id in SKIP_ENCAP_IDS:
            continue
        if encap_id not in ENCAP_REGISTRY:
            continue
        # Ensure state entry exists
        _ = state.get_encap_state(encap_id)
    state.save(state_path)

    # ---- Parse encap range ----
    encap_range = None
    if args.encap_range:
        parts = args.encap_range.split("-")
        encap_range = (int(parts[0]), int(parts[1]))
        log.info(f"Encap range filter: {encap_range[0]}-{encap_range[1]}")

    # ---- Build queue ----
    queue = build_fuzz_queue(state, encap_range=encap_range)
    total_todo = len(queue)
    if encap_range:
        total_encaps = sum(1 for eid in range(encap_range[0], encap_range[1] + 1)
                           if eid not in SKIP_ENCAP_IDS and eid in ENCAP_REGISTRY)
    else:
        total_encaps = sum(1 for eid in range(0, max_id + 1)
                           if eid not in SKIP_ENCAP_IDS and eid in ENCAP_REGISTRY)
    already_done = total_encaps - total_todo

    log.info(f"=== Phase 2: Fuzzing {total_todo} encaps "
             f"({already_done} already done, {total_encaps} total) ===")

    print_progress(state, console)

    # ---- Fuzz loop ----
    interrupted = False
    for idx, encap_id in enumerate(queue, 1):
        encap = ENCAP_REGISTRY.get(encap_id)
        if not encap:
            continue

        es = state.get_encap_state(encap_id)

        console.print()
        console.print("[bold cyan]" + "-" * 60 + "[/bold cyan]")
        log.info(f"[{already_done + idx}/{total_encaps}] "
                 f"Fuzzing: {encap.name} (WTAP {encap.id}) — {encap.full_name}")
        if es.seed_count > 0:
            log.info(f"  Seeds available: {es.seed_count} packets from pcaps")
        else:
            log.info(f"  No seeds — using synthetic minimal corpus")
        console.print("[bold cyan]" + "-" * 60 + "[/bold cyan]")

        try:
            result = fuzz_encap(
                encap=encap,
                state=state,
                campaign_dir=campaign_dir,
                pcap_dir=pcap_dir,
                log=log,
                console=console,
            )

            if result.crashes > 0:
                log.ok(f"  CRASHES FOUND: {result.crashes} crash file(s) "
                       f"in {result.run_dir}")
            else:
                log.ok(f"  Done: corpus={result.corpus_count}, "
                       f"elapsed={result.elapsed_secs}s")

        except KeyboardInterrupt:
            log.warn("Campaign interrupted by user (Ctrl+C)")
            log.info("Progress saved. Resume with --resume")
            interrupted = True
            break
        except Exception as exc:
            log.err(f"  Unexpected error: {exc}")
            # Mark as failed and continue
            es = state.get_encap_state(encap_id)
            es.status = "failed"
            es.error = str(exc)[:500]
            es.finished_at = datetime.now().isoformat()
            state.set_encap_state(es)
            state.save(state_path)
            continue

    # ---- Final summary ----
    console.print()
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
    if interrupted:
        console.print("[bold yellow]  Campaign paused — resume with --resume[/bold yellow]")
    else:
        console.print("[bold green]  Campaign complete![/bold green]")
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")

    print_progress(state, console)

    # Summary of crashes
    all_crashes = []
    for _, ed in state.encaps.items():
        if ed.get("crashes", 0) > 0:
            all_crashes.append(ed)

    if all_crashes:
        console.print("[bold red]Encap types with crashes:[/bold red]")
        crash_table = Table(show_lines=False)
        crash_table.add_column("Encap", style="bold")
        crash_table.add_column("WTAP ID", justify="right")
        crash_table.add_column("Crashes", justify="right", style="red")
        crash_table.add_column("Run Directory")
        for ed in sorted(all_crashes, key=lambda x: -x.get("crashes", 0)):
            crash_table.add_row(
                ed.get("encap_name", "?"),
                str(ed.get("encap_id", "?")),
                str(ed.get("crashes", 0)),
                ed.get("run_dir", ""),
            )
        console.print(crash_table)
        console.print()
    else:
        console.print("[dim]No crashes found across any encap type.[/dim]")
        console.print()

    log.info(f"State saved to: {state_path}")
    log.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="wirefuzz campaign — fuzz every encap type systematically",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # New campaign — scan pcaps, then fuzz all encaps
  python wirefuzz_campaign.py /data/pcaps -V master -w 60 -d 60m -o campaign_run

  # Resume after interruption
  python wirefuzz_campaign.py --resume -o campaign_run

  # Custom settings
  python wirefuzz_campaign.py /data/pcaps -V v4.6.4 -w 32 -d 2h --max-len 32768
""",
    )

    parser.add_argument(
        "pcap_dir", nargs="?", default=None,
        help="Directory with pcap/pcapng files (scanned recursively)",
    )
    parser.add_argument(
        "-V", "--version", dest="ws_version", default=None,
        help="Wireshark version to fuzz (tag, branch, or commit hash)",
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=None,
        help=f"Number of libfuzzer fork workers per encap (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "-d", "--duration", default=None,
        help=f"Duration per encap, e.g. '60m', '2h', '3600s' (default: {DEFAULT_DURATION})",
    )
    parser.add_argument(
        "-o", "--output", default="wirefuzz_campaign",
        help="Campaign output directory (default: wirefuzz_campaign)",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume a previous campaign from its state file",
    )
    parser.add_argument(
        "--max-len", type=int, default=CONFIG.default_max_len,
        help=f"Max input length in bytes (default: {CONFIG.default_max_len})",
    )
    parser.add_argument(
        "--timeout-ms", type=int, default=CONFIG.default_timeout_ms,
        help=f"Per-input timeout in ms (default: {CONFIG.default_timeout_ms})",
    )
    parser.add_argument(
        "--rss-limit-mb", type=int, default=CONFIG.default_rss_limit_mb,
        help=f"RSS limit per worker in MB (default: {CONFIG.default_rss_limit_mb})",
    )
    parser.add_argument(
        "--max-scan-packets", type=int, default=DEFAULT_MAX_SCAN_PACKETS,
        help=f"Max total packets to read during pcap scan/categorization phase (default: {DEFAULT_MAX_SCAN_PACKETS:,})",
    )
    parser.add_argument(
        "--max-extract-packets", type=int, default=DEFAULT_MAX_EXTRACT_PACKETS,
        help=f"Max packets to extract per encap for seed corpus (default: {DEFAULT_MAX_EXTRACT_PACKETS:,})",
    )
    parser.add_argument(
        "--encap-range", default=None,
        help="Encap ID range to fuzz, e.g. '0-50' or '100-227' (default: all)",
    )
    parser.add_argument(
        "--no-dashboard", action="store_true",
        help="Disable the web dashboard",
    )
    parser.add_argument(
        "--dashboard-port", type=int, default=56789,
        help="Dashboard HTTP port (default: 56789)",
    )
    parser.add_argument(
        "--dashboard-password", default="helloworld",
        help="Dashboard password (default: helloworld)",
    )

    args = parser.parse_args()

    # Validate
    if not args.resume and not args.pcap_dir:
        parser.error("pcap_dir is required for a new campaign (or use --resume)")
    if not args.resume and not args.ws_version:
        parser.error("-V/--version is required for a new campaign")

    run_campaign(args)


if __name__ == "__main__":
    main()
