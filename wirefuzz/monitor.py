"""Live fuzzing stats monitor - parses libfuzzer output."""

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.table import Table


@dataclass
class FuzzStats:
    total_execs: int = 0
    exec_per_sec: int = 0
    corpus_entries: int = 0
    corpus_size_bytes: int = 0
    features: int = 0
    coverage: int = 0
    crashes: int = 0
    timeouts: int = 0
    ooms: int = 0
    peak_rss_mb: int = 0
    start_time: Optional[str] = None
    last_update: Optional[str] = None


# Regex patterns for libfuzzer output lines
# Example: #1234    REDUCE cov: 567 ft: 890 corp: 12/3456b lim: 65535 exec/s: 789 rss: 123Mb
STATS_RE = re.compile(
    r'#(\d+)\s+'
    r'(?:NEW|REDUCE|pulse|RELOAD|INITED|DONE|BINGO)\s+'
    r'cov:\s*(\d+)\s+'
    r'ft:\s*(\d+)\s+'
    r'corp:\s*(\d+)/(\d+)([bKMG]?)\s+'
    r'(?:lim:\s*\d+\s+)?'
    r'exec/s:\s*(\d+)\s+'
    r'rss:\s*(\d+)Mb'
)

# Fork mode summary line
# Example: SUMMARY: exec/s: 1234, ...
SUMMARY_RE = re.compile(r'SUMMARY.*exec/s:\s*(\d+)')

# Crash/timeout/OOM detection
CRASH_RE = re.compile(r'(SUMMARY|==\d+==).*?(ASAN|UBSAN|AddressSanitizer|UndefinedBehavior|ERROR|SEGV|ABRT)')
TIMEOUT_RE = re.compile(r'ALARM.*timeout')
OOM_RE = re.compile(r'out-of-memory|rss_limit_mb')

# Artifact saved
ARTIFACT_RE = re.compile(r'artifact_prefix.*crash-|Test unit written to.*/crash')


def parse_fuzzer_line(line: str, stats: FuzzStats) -> bool:
    """Parse a single line of libfuzzer output and update stats.

    Returns True if stats were updated.
    """
    m = STATS_RE.search(line)
    if m:
        stats.total_execs = int(m.group(1))
        stats.coverage = int(m.group(2))
        stats.features = int(m.group(3))
        stats.corpus_entries = int(m.group(4))

        size_val = int(m.group(5))
        size_unit = m.group(6)
        if size_unit == 'K':
            size_val *= 1024
        elif size_unit == 'M':
            size_val *= 1024 * 1024
        elif size_unit == 'G':
            size_val *= 1024 * 1024 * 1024
        stats.corpus_size_bytes = size_val

        stats.exec_per_sec = int(m.group(7))
        stats.peak_rss_mb = max(stats.peak_rss_mb, int(m.group(8)))
        stats.last_update = datetime.now().isoformat()
        return True

    m = SUMMARY_RE.search(line)
    if m:
        stats.exec_per_sec = int(m.group(1))
        stats.last_update = datetime.now().isoformat()
        return True

    if ARTIFACT_RE.search(line):
        stats.crashes += 1
        stats.last_update = datetime.now().isoformat()
        return True

    if TIMEOUT_RE.search(line):
        stats.timeouts += 1
        return True

    if OOM_RE.search(line):
        stats.ooms += 1
        return True

    return False


def _format_size(bytes_val: int) -> str:
    """Format byte count to human readable."""
    if bytes_val < 1024:
        return f"{bytes_val}b"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f}KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.1f}MB"
    else:
        return f"{bytes_val / (1024 * 1024 * 1024):.1f}GB"


def _build_stats_table(stats: FuzzStats, run_dir: Path = None) -> Table:
    """Build a rich table showing current fuzzing stats."""
    table = Table(title="Fuzzing Stats", show_lines=False, expand=True)
    table.add_column("Metric", style="bold", width=20)
    table.add_column("Value", width=25)
    table.add_column("Metric", style="bold", width=20)
    table.add_column("Value", width=25)

    # Row 1
    table.add_row(
        "Executions", f"{stats.total_execs:,}",
        "Exec/s", f"{stats.exec_per_sec:,}",
    )
    # Row 2
    table.add_row(
        "Corpus entries", f"{stats.corpus_entries:,}",
        "Corpus size", _format_size(stats.corpus_size_bytes),
    )
    # Row 3
    crash_style = "bold red" if stats.crashes > 0 else ""
    table.add_row(
        "Coverage", f"{stats.coverage:,}",
        "Features", f"{stats.features:,}",
    )
    # Row 4
    table.add_row(
        "Crashes", f"[{crash_style}]{stats.crashes}[/{crash_style}]" if crash_style else str(stats.crashes),
        "Peak RSS", f"{stats.peak_rss_mb}MB",
    )
    # Row 5
    table.add_row(
        "Timeouts", str(stats.timeouts),
        "OOMs", str(stats.ooms),
    )

    if stats.last_update:
        table.add_row(
            "Last update", stats.last_update[:19],
            "", "",
        )

    return table


def display_live_stats(run_dir: Path, console: Console = None):
    """Display live stats from a running fuzz session's log file.

    Tails the fuzz.log file and updates a live table every 2 seconds.
    """
    console = console or Console()
    log_path = run_dir / "logs" / "fuzz.log"

    if not log_path.exists():
        console.print(f"[yellow]Log file not found: {log_path}[/yellow]")
        console.print("[dim]The fuzzing session may not have started yet.[/dim]")
        return

    # Load metadata
    meta_path = run_dir / "run.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
        console.print(f"  Run: [bold]{run_dir.name}[/bold]")
        console.print(f"  Encap: {meta.get('encap_name', '?')} ({meta.get('encap_id', '?')})")
        console.print(f"  Version: {meta.get('version', '?')}")
        console.print()

    stats = FuzzStats()

    # Parse existing log content
    with open(log_path, "r") as f:
        for line in f:
            parse_fuzzer_line(line.strip(), stats)

    # Display current stats
    table = _build_stats_table(stats, run_dir)
    console.print(table)

    # Tail mode: watch for new lines
    console.print("\n[dim]Watching for updates (Ctrl+C to stop)...[/dim]\n")

    try:
        with open(log_path, "r") as f:
            f.seek(0, 2)  # Seek to end

            with Live(_build_stats_table(stats, run_dir),
                       console=console, refresh_per_second=1) as live:
                while True:
                    line = f.readline()
                    if line:
                        if parse_fuzzer_line(line.strip(), stats):
                            live.update(_build_stats_table(stats, run_dir))

                            # Also update status.json
                            from wirefuzz.dashboard import update_status
                            update_status(run_dir, {
                                "total_execs": stats.total_execs,
                                "exec_per_sec": stats.exec_per_sec,
                                "corpus_entries": stats.corpus_entries,
                                "crashes": stats.crashes,
                                "features": stats.features,
                                "coverage": stats.coverage,
                                "peak_rss_mb": stats.peak_rss_mb,
                            })
                    else:
                        time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    console.print("\n[dim]Monitoring stopped.[/dim]")
