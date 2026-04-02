"""Run directory management and naming for dashboard compatibility."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.table import Table

from wirefuzz.config import CONFIG
from wirefuzz.encaps import EncapType


def create_run_dir(base: Path, encap: EncapType, version: str) -> Path:
    """Create a uniquely named run directory for a fuzz session.

    Naming: {encap_name}_{encap_id}_{version}_{YYYYMMDD_HHMMSS}/
    Creates subdirectories: corpus/, crashes/, logs/, coverage/
    """
    name = encap.name.lower()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dirname = f"{name}_{encap.id}_{version}_{timestamp}"

    run_dir = base / dirname
    run_dir.mkdir(parents=True, exist_ok=True)

    for subdir in ["corpus", "crashes", "logs", "coverage"]:
        (run_dir / subdir).mkdir(exist_ok=True)

    return run_dir


def write_run_metadata(run_dir: Path, config: dict):
    """Write run.json metadata file for a fuzz session."""
    metadata = {
        "created": datetime.now().isoformat(),
        "run_dir": str(run_dir),
        **config,
    }
    (run_dir / "run.json").write_text(json.dumps(metadata, indent=2))


def read_run_metadata(run_dir: Path) -> Optional[dict]:
    """Read run.json metadata from a run directory."""
    meta_path = run_dir / "run.json"
    if not meta_path.exists():
        return None
    return json.loads(meta_path.read_text())


def update_status(run_dir: Path, stats: dict):
    """Write/update status.json with current fuzzing stats."""
    status = {
        "updated": datetime.now().isoformat(),
        **stats,
    }
    (run_dir / "status.json").write_text(json.dumps(status, indent=2))


def list_runs(base: Path) -> List[Dict]:
    """List all run directories with their metadata.

    Returns list of dicts sorted by creation time (newest first).
    """
    if not base.exists():
        return []

    runs = []
    for d in sorted(base.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        meta = read_run_metadata(d)
        if meta is None:
            continue

        # Count crashes and corpus entries
        crash_count = sum(1 for f in (d / "crashes").iterdir()
                         if f.is_file()) if (d / "crashes").exists() else 0
        corpus_count = sum(1 for f in (d / "corpus").iterdir()
                          if f.is_file()) if (d / "corpus").exists() else 0

        # Check if running
        status_path = d / "status.json"
        status = json.loads(status_path.read_text()) if status_path.exists() else {}

        runs.append({
            "dir": str(d),
            "name": d.name,
            "metadata": meta,
            "crashes": crash_count,
            "corpus": corpus_count,
            "status": status,
        })

    return runs


def display_runs(base: Path, console: Console = None):
    """Display all runs as a rich table."""
    console = console or Console()
    runs = list_runs(base)

    if not runs:
        console.print("[dim]No fuzz runs found.[/dim]")
        return

    table = Table(title="Fuzz Runs", show_lines=False)
    table.add_column("Run", style="bold")
    table.add_column("Version", style="dim")
    table.add_column("Encap", style="cyan")
    table.add_column("Corpus", justify="right")
    table.add_column("Crashes", justify="right", style="red")
    table.add_column("Created", style="dim")

    for r in runs:
        meta = r["metadata"]
        crash_style = "bold red" if r["crashes"] > 0 else ""
        table.add_row(
            r["name"],
            meta.get("version", "?"),
            f"{meta.get('encap_name', '?')} ({meta.get('encap_id', '?')})",
            str(r["corpus"]),
            f"[{crash_style}]{r['crashes']}[/{crash_style}]" if crash_style else str(r["crashes"]),
            meta.get("created", "?")[:19],
        )

    console.print()
    console.print(table)
    console.print()
