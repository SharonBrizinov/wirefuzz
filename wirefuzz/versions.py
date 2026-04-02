"""Wireshark version management: fetch tags, cache, interactive selection."""

import json as json_mod
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests
from rich.console import Console
from rich.table import Table

from wirefuzz.config import CONFIG
from wirefuzz.exceptions import GitLabApiError, VersionNotFoundError

# Regex for stable release tags: v4.4.14, v4.6.5
STABLE_TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")
# Regex for release candidates: v4.6.5rc0
RC_TAG_RE = re.compile(r"^v\d+\.\d+\.\d+rc\d+$")


def fetch_tags(refresh: bool = False, limit: int = 100) -> List[Dict]:
    """Fetch Wireshark release tags from GitLab API.

    Returns list of dicts: {"name": str, "date": str, "commit": str}.
    Results are cached in ~/.cache/wirefuzz/tags.json for 1 hour.
    """
    cache_path = CONFIG.cache_dir / "tags.json"

    # Check cache
    if not refresh and cache_path.exists():
        mtime = cache_path.stat().st_mtime
        if time.time() - mtime < CONFIG.tag_cache_ttl_seconds:
            return json_mod.loads(cache_path.read_text())

    # Fetch from GitLab
    url = f"{CONFIG.gitlab_api}/repository/tags"
    tags = []
    page = 1

    try:
        while len(tags) < limit:
            resp = requests.get(
                url,
                params={"per_page": min(100, limit - len(tags)), "page": page},
                timeout=15,
            )
            resp.raise_for_status()
            batch = resp.json()
            if not batch:
                break

            for tag in batch:
                commit_info = tag.get("commit", {})
                tags.append({
                    "name": tag["name"],
                    "date": commit_info.get("committed_date", "")[:10],
                    "commit": commit_info.get("id", "")[:12],
                })
            page += 1

    except requests.exceptions.ConnectionError:
        raise GitLabApiError("network unreachable")
    except requests.exceptions.Timeout:
        raise GitLabApiError("request timed out")
    except requests.exceptions.HTTPError as e:
        raise GitLabApiError(str(e))

    # Cache results
    CONFIG.cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json_mod.dumps(tags, indent=2))

    return tags


def get_cached_versions() -> Set[str]:
    """Return set of Wireshark versions with locally built Docker images."""
    try:
        result = subprocess.run(
            ["docker", "images", CONFIG.docker_image_prefix,
             "--format", "{{.Tag}}"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return set()
        return {
            line.strip() for line in result.stdout.strip().split("\n")
            if line.strip() and line.strip() != "<none>"
        }
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return set()


def filter_tags(tags: List[Dict], show_all: bool = False) -> List[Dict]:
    """Filter tags to stable releases only (unless show_all)."""
    if show_all:
        return tags
    return [t for t in tags if STABLE_TAG_RE.match(t["name"])]


def list_versions(show_all: bool = False, refresh: bool = False,
                  json_output: bool = False, console: Console = None):
    """Display available Wireshark versions with cache status."""
    console = console or Console()

    tags = fetch_tags(refresh=refresh)
    filtered = filter_tags(tags, show_all=show_all)
    cached = get_cached_versions()

    # Build version list with master at top
    versions = []
    versions.append({
        "name": "master",
        "date": "(latest)",
        "cached": "master" in cached,
    })
    for tag in filtered:
        versions.append({
            "name": tag["name"],
            "date": tag["date"],
            "cached": tag["name"] in cached,
        })

    if json_output:
        data = {
            "source": CONFIG.wireshark_repo,
            "versions": versions,
        }
        console.print_json(json_mod.dumps(data, indent=2))
        return

    # Rich table
    table = Table(title="Available Wireshark Versions", show_lines=False)
    table.add_column("Version", style="bold")
    table.add_column("Date", style="dim")
    table.add_column("Status")

    for v in versions:
        status = "[green]● cached (image ready)[/green]" if v["cached"] else ""
        table.add_row(v["name"], v["date"], status)

    console.print()
    console.print(f"  [dim]Source: {CONFIG.wireshark_repo}[/dim]")
    console.print()
    console.print(table)
    console.print()
    console.print("[dim]● = Docker image already built locally (ready to fuzz)[/dim]")
    console.print()


def select_version_interactive(console: Console = None) -> str:
    """Show interactive dropdown for version selection.

    Cached versions are sorted to the top. Falls back to latest stable
    if stdout is not a TTY.
    """
    console = console or Console()

    tags = fetch_tags()
    stable = filter_tags(tags)
    cached = get_cached_versions()

    if not stable:
        raise GitLabApiError("no releases found")

    # Build choices: cached first, then uncached, master always available
    choices = []

    # Cached versions first
    for tag in stable:
        if tag["name"] in cached:
            display = f"{tag['name']:16s} ({tag['date']})  ● cached"
            choices.append({"name": display, "value": tag["name"]})

    if "master" in cached:
        display = "master           (latest)      ● cached"
        choices.insert(0, {"name": display, "value": "master"})

    # Uncached versions
    if "master" not in cached:
        display = "master           (latest)"
        choices.append({"name": display, "value": "master"})

    for tag in stable:
        if tag["name"] not in cached:
            display = f"{tag['name']:16s} ({tag['date']})"
            choices.append({"name": display, "value": tag["name"]})

    # Non-TTY fallback
    if not sys.stdout.isatty():
        latest = stable[0]["name"]
        console.print(
            f"[yellow]Warning:[/yellow] Non-interactive mode, "
            f"defaulting to {latest}"
        )
        return latest

    # Interactive selection with InquirerPy
    try:
        from InquirerPy import inquirer

        version = inquirer.fuzzy(
            message="Select Wireshark version:",
            choices=[{"name": c["name"], "value": c["value"]} for c in choices],
            max_height="60%",
        ).execute()

        if isinstance(version, dict):
            version = version.get("value", version)

        return version

    except ImportError:
        # Fallback: simple numbered list
        console.print("\n[bold]Select Wireshark version:[/bold]\n")
        for i, c in enumerate(choices[:20], 1):
            console.print(f"  {i:3d}) {c['name']}")

        console.print()
        while True:
            try:
                choice = console.input("[bold]Enter number:[/bold] ")
                idx = int(choice) - 1
                if 0 <= idx < len(choices):
                    return choices[idx]["value"]
            except (ValueError, EOFError):
                pass
            console.print("[red]Invalid choice, try again.[/red]")


def is_commit_hash(version: str) -> bool:
    """Check if a version string looks like a git commit hash."""
    return bool(re.match(r'^[0-9a-f]{7,40}$', version))


def validate_version(version: str) -> Tuple[str, bool]:
    """Validate a version string.

    Returns (version, is_known) where is_known indicates if it was found
    in the GitLab tags. Unknown versions are still accepted (could be
    branches or commit hashes).
    """
    if version == "master":
        return version, True

    if is_commit_hash(version):
        return version, True

    try:
        tags = fetch_tags()
    except GitLabApiError:
        return version, False

    known_names = {t["name"] for t in tags}
    return version, version in known_names
