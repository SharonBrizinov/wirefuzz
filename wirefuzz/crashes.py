"""Crash collection, deduplication, and triage."""

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.table import Table


@dataclass
class CrashInfo:
    path: Path
    size: int
    crash_type: str = "unknown"
    stack_hash: str = ""
    top_frames: List[str] = field(default_factory=list)
    asan_output: str = ""


# Patterns for ASAN output classification
CRASH_TYPE_PATTERNS = [
    (re.compile(r'heap-buffer-overflow', re.I), "heap-buffer-overflow"),
    (re.compile(r'stack-buffer-overflow', re.I), "stack-buffer-overflow"),
    (re.compile(r'heap-use-after-free', re.I), "use-after-free"),
    (re.compile(r'stack-use-after-return', re.I), "stack-use-after-return"),
    (re.compile(r'double-free', re.I), "double-free"),
    (re.compile(r'alloc-dealloc-mismatch', re.I), "alloc-dealloc-mismatch"),
    (re.compile(r'global-buffer-overflow', re.I), "global-buffer-overflow"),
    (re.compile(r'use-of-uninitialized-value', re.I), "use-of-uninitialized-value"),
    (re.compile(r'null-dereference|SEGV.*null', re.I), "null-dereference"),
    (re.compile(r'SEGV|segmentation', re.I), "segfault"),
    (re.compile(r'ABRT|abort', re.I), "abort"),
    (re.compile(r'undefined-behavior|UndefinedBehavior', re.I), "undefined-behavior"),
    (re.compile(r'integer-overflow', re.I), "integer-overflow"),
    (re.compile(r'shift-exponent', re.I), "shift-exponent"),
    (re.compile(r'divide-by-zero|division.*zero', re.I), "divide-by-zero"),
    (re.compile(r'timeout', re.I), "timeout"),
    (re.compile(r'oom|out-of-memory', re.I), "oom"),
]

# Stack frame extraction
FRAME_RE = re.compile(r'#\d+\s+\S+\s+in\s+(\S+)\s')


def list_crashes(crash_dir: Path) -> List[CrashInfo]:
    """List all crash files in a directory with basic metadata."""
    if not crash_dir.exists():
        return []

    crashes = []
    for f in sorted(crash_dir.iterdir()):
        if not f.is_file():
            continue
        # libfuzzer names: crash-*, timeout-*, oom-*, slow-unit-*
        name = f.name.lower()
        if any(name.startswith(p) for p in ["crash-", "timeout-", "oom-", "slow-unit-", "leak-"]):
            crash_type = "unknown"
            if name.startswith("crash-"):
                crash_type = "crash"
            elif name.startswith("timeout-"):
                crash_type = "timeout"
            elif name.startswith("oom-"):
                crash_type = "oom"
            elif name.startswith("slow-unit-"):
                crash_type = "slow-unit"
            elif name.startswith("leak-"):
                crash_type = "leak"

            crashes.append(CrashInfo(
                path=f,
                size=f.stat().st_size,
                crash_type=crash_type,
            ))

    return crashes


def deduplicate_crashes(crashes: List[CrashInfo]) -> Dict[str, List[CrashInfo]]:
    """Group crashes by content hash (exact dedup).

    Returns dict mapping hash -> list of crashes with that hash.
    """
    groups: Dict[str, List[CrashInfo]] = {}

    for crash in crashes:
        try:
            content = crash.path.read_bytes()
            h = hashlib.sha256(content).hexdigest()[:16]
            crash.stack_hash = h
        except OSError:
            h = f"error_{crash.path.name}"

        if h not in groups:
            groups[h] = []
        groups[h].append(crash)

    return groups


def classify_crash(asan_output: str) -> tuple:
    """Classify crash type and extract stack frames from ASAN output.

    Returns (crash_type, top_frames).
    """
    crash_type = "unknown"
    for pattern, ctype in CRASH_TYPE_PATTERNS:
        if pattern.search(asan_output):
            crash_type = ctype
            break

    frames = FRAME_RE.findall(asan_output)
    top_frames = frames[:5] if frames else []

    return crash_type, top_frames


def display_crashes(run_dir: Path, console: Console = None):
    """Display crash information for a fuzz run."""
    console = console or Console()

    crash_dir = run_dir / "crashes"
    crashes = list_crashes(crash_dir)

    if not crashes:
        console.print("[dim]No crashes found.[/dim]")
        return

    # Deduplicate
    groups = deduplicate_crashes(crashes)

    console.print(f"\n  [bold]Crashes found: {len(crashes)}[/bold]")
    console.print(f"  Unique (by content hash): {len(groups)}\n")

    table = Table(title="Crash Files", show_lines=False)
    table.add_column("#", style="dim", width=4)
    table.add_column("File", style="bold")
    table.add_column("Size", justify="right")
    table.add_column("Type", style="cyan")
    table.add_column("Hash", style="dim")
    table.add_column("Dupes", justify="right")

    for i, (h, group) in enumerate(sorted(groups.items()), 1):
        crash = group[0]  # Representative
        size_str = f"{crash.size:,}b"
        table.add_row(
            str(i),
            crash.path.name,
            size_str,
            crash.crash_type,
            h,
            str(len(group)) if len(group) > 1 else "",
        )

    console.print(table)
    console.print()

    # Show paths for reproduction
    console.print("[bold]To reproduce:[/bold]")
    for h, group in sorted(groups.items()):
        crash = group[0]
        meta = _read_run_meta(run_dir)
        if meta:
            console.print(
                f"  wirefuzz fuzz --resume {run_dir} "
                f"# then: docker exec <container> /opt/wirefuzz/entrypoint.sh "
                f"reproduce /crashes/{crash.path.name}"
            )
        break  # Just show first example

    console.print()


def generate_crash_report(crash: CrashInfo, run_dir: Path) -> str:
    """Generate a formatted crash report for bug filing."""
    meta = _read_run_meta(run_dir)
    encap_name = meta.get("encap_name", "?") if meta else "?"
    encap_id = meta.get("encap_id", "?") if meta else "?"
    version = meta.get("version", "?") if meta else "?"

    report = []
    report.append(f"## Crash Report")
    report.append(f"")
    report.append(f"**Wireshark version:** {version}")
    report.append(f"**Encapsulation type:** {encap_name} ({encap_id})")
    report.append(f"**Crash type:** {crash.crash_type}")
    report.append(f"**Crash file:** {crash.path.name}")
    report.append(f"**Crash size:** {crash.size} bytes")
    report.append(f"")

    if crash.top_frames:
        report.append(f"### Stack trace (top frames)")
        report.append(f"```")
        for frame in crash.top_frames:
            report.append(f"  {frame}")
        report.append(f"```")
        report.append(f"")

    if crash.asan_output:
        report.append(f"### ASAN output")
        report.append(f"```")
        report.append(crash.asan_output[:2000])
        report.append(f"```")
        report.append(f"")

    report.append(f"### Reproduction")
    report.append(f"```bash")
    report.append(f"WIREFUZZ_ENCAP={encap_id} FUZZSHARK_TARGET=frame "
                  f"./fuzzshark crash_file")
    report.append(f"```")

    return "\n".join(report)


def _read_run_meta(run_dir: Path) -> Optional[dict]:
    """Read run.json metadata."""
    meta_path = run_dir / "run.json"
    if meta_path.exists():
        return json.loads(meta_path.read_text())
    return None
