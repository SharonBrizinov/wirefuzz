"""Fuzzer orchestration: launch and manage libfuzzer sessions in Docker."""

import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console

from wirefuzz.config import CONFIG
from wirefuzz.dashboard import create_run_dir, write_run_metadata
from wirefuzz.docker import check_docker, run_container, stop_container
from wirefuzz.encaps import EncapType


@dataclass
class FuzzSession:
    run_dir: Path
    version: str
    encap: EncapType
    workers: int
    container_name: str
    started: str = field(default_factory=lambda: datetime.now().isoformat())


def _merge_corpus_pcapng(run_dir: Path, encap: EncapType, console: Console):
    """Merge all corpus files into a single pcapng in the run directory."""
    from wirefuzz.corpus import write_pcapng

    corpus_dir = run_dir / "corpus"
    if not corpus_dir.exists():
        return

    files = sorted(f for f in corpus_dir.iterdir() if f.is_file())
    if not files:
        return

    console.print(f"  Merging {len(files)} corpus files into pcapng...")
    payloads = []
    for f in files:
        try:
            data = f.read_bytes()
            if data:
                payloads.append(data)
        except OSError:
            continue

    if not payloads:
        return

    out_path = run_dir / "corpus.pcapng"
    written = write_pcapng(payloads, encap.id, out_path)
    console.print(f"  [green]Saved {written} packets to {out_path}[/green]")


def start_fuzz_session(
    version: str,
    encap: EncapType,
    corpus_dir: Path,
    output_base: Path,
    workers: int = 0,
    max_len: int = None,
    timeout_ms: int = None,
    rss_limit_mb: int = None,
    duration: Optional[str] = None,
    dict_path: Optional[Path] = None,
    mount_source: Optional[Path] = None,
    pcap_source: Optional[Path] = None,
    samples_before_min: int = 0,
    samples_after_min: int = 0,
    verbose: bool = False,
    console: Console = None,
) -> FuzzSession:
    """Start a fuzzing session in a Docker container.

    Creates a run directory, copies seed corpus, and launches fuzzshark
    in a Docker container with the appropriate configuration.
    """
    console = console or Console()

    # Defaults
    if workers == 0:
        workers = CONFIG.default_workers
    if max_len is None:
        max_len = CONFIG.default_max_len
    if timeout_ms is None:
        timeout_ms = CONFIG.default_timeout_ms
    if rss_limit_mb is None:
        rss_limit_mb = CONFIG.default_rss_limit_mb

    # Create run directory
    run_dir = create_run_dir(output_base, encap, version)
    console.print(f"  Run directory: [bold]{run_dir}[/bold]")

    # Copy seed corpus to run directory
    run_corpus = run_dir / "corpus"
    corpus_dir = corpus_dir.resolve()
    if corpus_dir.is_dir():
        for f in corpus_dir.iterdir():
            if f.is_file():
                shutil.copy2(f, run_corpus / f.name)
    elif corpus_dir.is_file():
        shutil.copy2(corpus_dir, run_corpus / corpus_dir.name)

    corpus_count = sum(1 for f in run_corpus.iterdir() if f.is_file())
    console.print(f"  Seed corpus: {corpus_count} files")

    # Convert duration to seconds for libfuzzer
    duration_secs = _parse_duration(duration) if duration else 0

    # Container name
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    container_name = f"{CONFIG.docker_image_prefix}_{encap.name.lower()}_{encap.id}_{timestamp}"

    # Write run metadata
    metadata = {
        "version": version,
        "encap_id": encap.id,
        "encap_name": encap.name,
        "encap_full_name": encap.full_name,
        "workers": workers,
        "max_len": max_len,
        "timeout_ms": timeout_ms,
        "rss_limit_mb": rss_limit_mb,
        "duration": duration,
        "duration_secs": duration_secs,
        "container_name": container_name,
        "corpus_dir": str(corpus_dir),
        "seed_corpus_count": corpus_count,
        "pcap_source": str(pcap_source) if pcap_source else str(corpus_dir),
        "samples_before_min": samples_before_min,
        "samples_after_min": samples_after_min,
    }
    write_run_metadata(run_dir, metadata)

    # Environment variables
    env = {
        "WIREFUZZ_ENCAP": str(encap.id),
        "WIREFUZZ_WORKERS": str(workers),
        "WIREFUZZ_MAX_LEN": str(max_len),
        "WIREFUZZ_TIMEOUT": str(timeout_ms // 1000),  # libfuzzer uses seconds
        "WIREFUZZ_RSS_LIMIT": str(rss_limit_mb),
        "WIREFUZZ_DURATION": str(duration_secs),
        "FUZZSHARK_TARGET": "frame",
    }

    # Volume mounts
    volumes = {
        str(run_dir / "corpus"): "/corpus",
        str(run_dir / "crashes"): "/crashes",
        str(run_dir / "logs"): "/logs",
    }

    if dict_path and dict_path.exists():
        volumes[str(dict_path.parent.resolve())] = "/dict"

    if mount_source and mount_source.exists():
        volumes[str(mount_source.resolve())] = "/src/wireshark:ro"

    # tmpfs for scratch performance
    tmpfs = {
        "/tmp": f"exec,size={CONFIG.tmpfs_size}",
    }

    session = FuzzSession(
        run_dir=run_dir,
        version=version,
        encap=encap,
        workers=workers,
        container_name=container_name,
    )

    console.print()
    console.print(f"  [bold]Starting fuzzing session[/bold]")
    console.print(f"  Encap:      {encap.name} ({encap.id}) - {encap.full_name}")
    console.print(f"  Version:    {version}")
    console.print(f"  Workers:    {workers}")
    console.print(f"  Max len:    {max_len}")
    console.print(f"  Timeout:    {timeout_ms}ms")
    console.print(f"  RSS limit:  {rss_limit_mb}MB")
    if duration:
        console.print(f"  Duration:   {duration}")
    console.print(f"  Container:  {container_name}")
    console.print()

    # Launch container and stream output
    log_path = run_dir / "logs" / "session.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    from wirefuzz.monitor import FuzzStats, parse_fuzzer_line
    import re as _re

    stats = FuzzStats()
    stats.start_time = session.started
    corpus_after_min = [0]  # mutable container to allow update from inner scope

    def _print_summary():
        from datetime import datetime as _dt
        ended = _dt.now().isoformat()
        # Elapsed time
        try:
            started_dt = _dt.fromisoformat(session.started)
            elapsed_secs = int((_dt.now() - started_dt).total_seconds())
            h, rem = divmod(elapsed_secs, 3600)
            m, s = divmod(rem, 60)
            elapsed_str = f"{h}h {m}m {s}s" if h else f"{m}m {s}s"
        except Exception:
            elapsed_str = "unknown"

        # Corpus files currently on disk
        corpus_on_disk = sum(1 for f in (run_dir / "corpus").iterdir()
                             if f.is_file()) if (run_dir / "corpus").exists() else 0
        crash_files = sorted(f for f in (run_dir / "crashes").iterdir()
                             if f.is_file()) if (run_dir / "crashes").exists() else []

        console.print()
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
        console.print("[bold]  wirefuzz session summary[/bold]")
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
        console.print()

        # Session config
        console.print("[bold]  Configuration[/bold]")
        console.print(f"    Wireshark version:  {version}")
        console.print(f"    Encap type:         {encap.name} (WTAP {encap.id}) — {encap.full_name}")
        console.print(f"    Workers:            {workers}")
        console.print(f"    Max input length:   {max_len} bytes")
        console.print(f"    Timeout per input:  {timeout_ms} ms")
        console.print(f"    RSS limit:          {rss_limit_mb} MB")
        console.print(f"    Duration limit:     {duration or 'unlimited'}")
        console.print()

        # Corpus pipeline
        console.print("[bold]  Corpus pipeline[/bold]")
        src = str(pcap_source) if pcap_source else str(corpus_dir)
        console.print(f"    Source:             {src}")
        console.print(f"    Samples extracted:  {samples_before_min}")
        console.print(f"    After dedup:        {corpus_count} (SHA-256 unique)")
        if corpus_after_min[0]:
            console.print(f"    After minimization: {corpus_after_min[0]} (coverage unique)")
        console.print(f"    Corpus on disk now: {corpus_on_disk}")
        console.print()

        # Fuzzing stats
        console.print("[bold]  Fuzzing stats[/bold]")
        console.print(f"    Started:            {session.started[:19]}")
        console.print(f"    Ended:              {ended[:19]}")
        console.print(f"    Elapsed:            {elapsed_str}")
        console.print(f"    Total executions:   {stats.total_execs:,}")
        console.print(f"    Exec/s:             {stats.exec_per_sec:,}")
        console.print(f"    Coverage edges:     {stats.coverage:,}")
        console.print(f"    Features:           {stats.features:,}")
        console.print(f"    Peak RSS:           {stats.peak_rss_mb} MB")
        if stats.timeouts:
            console.print(f"    Timeouts:           {stats.timeouts}")
        if stats.ooms:
            console.print(f"    OOMs:               {stats.ooms}")
        console.print()

        # Crashes
        if crash_files:
            console.print(f"[bold red]  Crashes ({len(crash_files)} files)[/bold red]")
            for cf in crash_files[:10]:
                console.print(f"    {cf}")
            if len(crash_files) > 10:
                console.print(f"    ... and {len(crash_files) - 10} more")
        else:
            console.print("[bold]  Crashes[/bold]")
            console.print("    None found")
        console.print()

        # Paths
        console.print("[bold]  Output paths[/bold]")
        console.print(f"    Run dir:   {run_dir}")
        console.print(f"    Corpus:    {run_dir / 'corpus'}")
        pcapng_path = run_dir / "corpus.pcapng"
        if pcapng_path.exists():
            size_mb = pcapng_path.stat().st_size / (1024 * 1024)
            console.print(f"    Pcapng:    {pcapng_path} ({size_mb:.1f} MB)")
        console.print(f"    Crashes:   {run_dir / 'crashes'}")
        console.print(f"    Logs:      {run_dir / 'logs'}")
        console.print()
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
        console.print()

    try:
        with open(log_path, "w", buffering=1) as log_file:
            log_file.write(f"=== wirefuzz session log ===\n")
            log_file.write(f"started:    {session.started}\n")
            log_file.write(f"version:    {version}\n")
            log_file.write(f"encap:      {encap.name} ({encap.id}) - {encap.full_name}\n")
            log_file.write(f"workers:    {workers}\n")
            log_file.write(f"max_len:    {max_len}\n")
            log_file.write(f"timeout_ms: {timeout_ms}\n")
            log_file.write(f"rss_limit:  {rss_limit_mb}MB\n")
            log_file.write(f"duration:   {duration or 'unlimited'}\n")
            log_file.write(f"container:  {container_name}\n")
            log_file.write(f"corpus:     {corpus_count} seed files\n")
            log_file.write(f"{'=' * 40}\n\n")

            for line in run_container(
                version=version,
                env=env,
                volumes=volumes,
                tmpfs=tmpfs,
                container_name=container_name,
                command="fuzz",
                verbose=verbose,
                console=console,
            ):
                console.print(f"  {line}")
                log_file.write(line + "\n")
                parse_fuzzer_line(line, stats)
                # Parse minimization result from entrypoint output
                # e.g. "Minimization complete: 500 -> 123 files"
                m = _re.search(r'Minimization complete.*?(\d+)\s*->\s*(\d+)', line)
                if m:
                    corpus_after_min[0] = int(m.group(2))

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted. Stopping container...[/yellow]")
        stop_container(container_name, console=console)
        _merge_corpus_pcapng(run_dir, encap, console)
        _print_summary()
        raise

    _merge_corpus_pcapng(run_dir, encap, console)
    _print_summary()
    return session


def stop_session(run_dir: Path, console: Console = None):
    """Stop a running fuzz session by reading its metadata."""
    console = console or Console()
    meta_path = run_dir / "run.json"
    if not meta_path.exists():
        console.print(f"[red]No run.json found in {run_dir}[/red]")
        return

    meta = json.loads(meta_path.read_text())
    container_name = meta.get("container_name")
    if container_name:
        stop_container(container_name, console=console)
    else:
        console.print("[yellow]No container name in metadata[/yellow]")


def resume_session(run_dir: Path, verbose: bool = False,
                   console: Console = None):
    """Resume a previous fuzz session from its run directory."""
    console = console or Console()
    meta_path = run_dir / "run.json"
    if not meta_path.exists():
        console.print(f"[red]No run.json found in {run_dir}[/red]")
        return

    meta = json.loads(meta_path.read_text())

    from wirefuzz.encaps import ENCAP_REGISTRY
    encap = ENCAP_REGISTRY.get(meta["encap_id"])
    if not encap:
        console.print(f"[red]Unknown encap ID: {meta['encap_id']}[/red]")
        return

    console.print(f"  Resuming session: [bold]{run_dir.name}[/bold]")
    console.print(f"  Encap: {encap.name} ({encap.id})")
    console.print(f"  Version: {meta['version']}")

    # Reuse the existing run directory's corpus and crashes
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    container_name = f"{CONFIG.docker_image_prefix}_{encap.name.lower()}_{encap.id}_{timestamp}"

    env = {
        "WIREFUZZ_ENCAP": str(encap.id),
        "WIREFUZZ_WORKERS": str(meta.get("workers", 4)),
        "WIREFUZZ_MAX_LEN": str(meta.get("max_len", CONFIG.default_max_len)),
        "WIREFUZZ_TIMEOUT": str(meta.get("timeout_ms", CONFIG.default_timeout_ms) // 1000),
        "WIREFUZZ_RSS_LIMIT": str(meta.get("rss_limit_mb", CONFIG.default_rss_limit_mb)),
        "WIREFUZZ_DURATION": str(meta.get("duration_secs", 0)),
        "FUZZSHARK_TARGET": "frame",
    }

    volumes = {
        str(run_dir / "corpus"): "/corpus",
        str(run_dir / "crashes"): "/crashes",
        str(run_dir / "logs"): "/logs",
    }

    tmpfs = {"/tmp": f"exec,size={CONFIG.tmpfs_size}"}

    from wirefuzz.monitor import FuzzStats, parse_fuzzer_line

    stats = FuzzStats()

    def _print_summary():
        console.print()
        console.print("[bold]Session summary[/bold]")
        console.print(f"  Run dir:     {run_dir}")
        console.print(f"  Logs:        {run_dir / 'logs'}")
        console.print(f"  Crashes:     {run_dir / 'crashes'}")
        console.print(f"  Corpus:      {run_dir / 'corpus'}")
        console.print()
        console.print(f"  Executions:  {stats.total_execs:,}")
        console.print(f"  Exec/s:      {stats.exec_per_sec:,}")
        console.print(f"  Coverage:    {stats.coverage:,}")
        console.print(f"  Features:    {stats.features:,}")
        console.print(f"  Corpus:      {stats.corpus_entries:,} entries")
        console.print(f"  Peak RSS:    {stats.peak_rss_mb} MB")
        crash_val = f"[bold red]{stats.crashes}[/bold red]" if stats.crashes else "0"
        console.print(f"  Crashes:     {crash_val}")
        crash_files = [f for f in (run_dir / "crashes").iterdir()
                       if f.is_file()] if (run_dir / "crashes").exists() else []
        if crash_files:
            console.print(f"\n  [bold red]Crash files ({len(crash_files)}):[/bold red]")
            for cf in sorted(crash_files)[:10]:
                console.print(f"    {cf}")
            if len(crash_files) > 10:
                console.print(f"    ... and {len(crash_files) - 10} more")
        console.print()

    log_path = run_dir / "logs" / "session.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(log_path, "a", buffering=1) as log_file:
            log_file.write(f"\n=== resumed {datetime.now().isoformat()} ===\n")
            for line in run_container(
                version=meta["version"],
                env=env,
                volumes=volumes,
                tmpfs=tmpfs,
                container_name=container_name,
                command="fuzz",
                verbose=verbose,
                console=console,
            ):
                console.print(f"  {line}")
                log_file.write(line + "\n")
                parse_fuzzer_line(line, stats)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted. Stopping container...[/yellow]")
        stop_container(container_name, console=console)
        _print_summary()
        raise


def _parse_duration(duration_str: str) -> int:
    """Parse duration string (e.g., '2h', '30m', '3600s', 'forever') to seconds."""
    if not duration_str or duration_str.lower() == "forever":
        return 0

    duration_str = duration_str.strip().lower()

    if duration_str.endswith("h"):
        return int(float(duration_str[:-1]) * 3600)
    elif duration_str.endswith("m"):
        return int(float(duration_str[:-1]) * 60)
    elif duration_str.endswith("s"):
        return int(float(duration_str[:-1]))
    else:
        return int(duration_str)
