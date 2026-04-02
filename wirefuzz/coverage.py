"""Coverage tracking via SanitizerCoverage (sancov)."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.table import Table

from wirefuzz.config import CONFIG
from wirefuzz.docker import run_container


@dataclass
class CoverageStats:
    total_edges: int = 0
    covered_edges: int = 0
    edge_coverage_pct: float = 0.0
    total_functions: int = 0
    covered_functions: int = 0
    function_coverage_pct: float = 0.0
    files: Dict[str, dict] = field(default_factory=dict)


def collect_coverage(
    run_dir: Path,
    version: str = None,
    console: Console = None,
) -> Optional[CoverageStats]:
    """Collect coverage data from a fuzz run using llvm-cov.

    Runs the corpus through fuzzshark with coverage instrumentation
    and generates a coverage report.
    """
    console = console or Console()

    # Read metadata
    meta_path = run_dir / "run.json"
    if not meta_path.exists():
        console.print("[red]No run.json found[/red]")
        return None

    meta = json.loads(meta_path.read_text())
    version = version or meta.get("version", "master")
    encap_id = meta.get("encap_id", 0)

    corpus_dir = run_dir / "corpus"
    cov_dir = run_dir / "coverage"
    cov_dir.mkdir(exist_ok=True)

    corpus_count = sum(1 for f in corpus_dir.iterdir() if f.is_file())
    console.print(f"  Collecting coverage for {corpus_count} corpus entries...")

    # Run fuzzshark with -merge=1 to get coverage stats
    # The merge output includes coverage information
    env = {
        "WIREFUZZ_ENCAP": str(encap_id),
        "FUZZSHARK_TARGET": "frame",
        "LLVM_PROFILE_FILE": "/coverage/fuzzshark.profraw",
    }

    volumes = {
        str(corpus_dir): "/corpus:ro",
        str(cov_dir): "/coverage",
    }

    tmpfs = {"/tmp": f"exec,size={CONFIG.tmpfs_size}"}

    stats = CoverageStats()

    try:
        for line in run_container(
            version=version,
            env=env,
            volumes=volumes,
            tmpfs=tmpfs,
            command="minimize",
            console=console,
        ):
            # Parse merge output for coverage info
            # libfuzzer merge reports: "MERGE-OUTER: N files, N edges"
            if "MERGE" in line and "edge" in line.lower():
                import re
                m = re.search(r'(\d+)\s+edge', line)
                if m:
                    stats.covered_edges = int(m.group(1))
            if "cov:" in line:
                import re
                m = re.search(r'cov:\s*(\d+)', line)
                if m:
                    stats.covered_edges = max(stats.covered_edges, int(m.group(1)))
    except Exception as e:
        console.print(f"[yellow]Coverage collection error: {e}[/yellow]")

    # Save stats
    stats_dict = {
        "covered_edges": stats.covered_edges,
        "corpus_count": corpus_count,
        "version": version,
        "encap_id": encap_id,
    }
    (cov_dir / "coverage.json").write_text(json.dumps(stats_dict, indent=2))

    return stats


def display_coverage(run_dir: Path, console: Console = None):
    """Display coverage information for a fuzz run."""
    console = console or Console()

    cov_path = run_dir / "coverage" / "coverage.json"
    if not cov_path.exists():
        console.print("[dim]No coverage data. Run 'wirefuzz coverage collect' first.[/dim]")
        return

    data = json.loads(cov_path.read_text())

    table = Table(title="Coverage Summary", show_lines=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Covered edges", f"{data.get('covered_edges', 0):,}")
    table.add_row("Corpus entries", f"{data.get('corpus_count', 0):,}")
    table.add_row("Version", data.get("version", "?"))
    table.add_row("Encap ID", str(data.get("encap_id", "?")))

    console.print()
    console.print(table)
    console.print()
