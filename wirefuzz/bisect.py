"""Crash bisection across Wireshark versions."""

import json
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from rich.console import Console

from wirefuzz.config import CONFIG
from wirefuzz.docker import build_image, check_docker, image_exists, run_container
from wirefuzz.encaps import EncapType


def get_version_list(good: str, bad: str, console: Console = None) -> List[str]:
    """Get ordered list of Wireshark versions between good and bad.

    Uses GitLab tags sorted by date. If good/bad are commit hashes,
    falls back to git log.
    """
    console = console or Console()

    from wirefuzz.versions import fetch_tags, filter_tags

    tags = fetch_tags()
    stable = filter_tags(tags)

    # Find indices
    names = [t["name"] for t in stable]

    good_idx = None
    bad_idx = None
    for i, name in enumerate(names):
        if name == good:
            good_idx = i
        if name == bad:
            bad_idx = i

    if good_idx is None or bad_idx is None:
        console.print(
            "[yellow]Could not find both versions in tag list. "
            "Bisection requires known release tags.[/yellow]"
        )
        return []

    # Tags are newest first, so bad_idx < good_idx (bad is newer)
    if bad_idx > good_idx:
        bad_idx, good_idx = good_idx, bad_idx

    return names[bad_idx:good_idx + 1]


def test_crash_on_version(
    crash_file: Path,
    version: str,
    encap: EncapType,
    console: Console = None,
) -> bool:
    """Test if a crash reproduces on a specific Wireshark version.

    Returns True if the crash reproduces (non-zero exit code).
    """
    console = console or Console()

    # Ensure image exists
    if not image_exists(version):
        console.print(f"  Building image for {version}...")
        build_image(version, verbose=False, console=console)

    env = {
        "WIREFUZZ_ENCAP": str(encap.id),
        "FUZZSHARK_TARGET": "frame",
    }

    volumes = {
        str(crash_file.parent.resolve()): "/crashes:ro",
    }

    crash_name = crash_file.name

    try:
        for line in run_container(
            version=version,
            env=env,
            volumes=volumes,
            command="reproduce",
            extra_args=[f"/crashes/{crash_name}"],
            console=console,
        ):
            if "reproduced" in line.lower():
                return True
            if "did NOT reproduce" in line.lower():
                return False
    except Exception:
        # Container crashed = crash reproduced
        return True

    return False


def bisect_crash(
    crash_file: Path,
    good_version: str,
    bad_version: str,
    encap: EncapType,
    console: Console = None,
) -> Optional[str]:
    """Binary search for the version that introduced a crash.

    Args:
        crash_file: Path to crash reproducer file.
        good_version: Version where crash does NOT reproduce.
        bad_version: Version where crash DOES reproduce.
        encap: Encapsulation type for the crash.
        console: Rich console.

    Returns:
        The first bad version (version where crash was introduced),
        or None if bisection fails.
    """
    console = console or Console()

    console.print(f"\n  [bold]Bisecting crash:[/bold] {crash_file.name}")
    console.print(f"  Good (no crash): {good_version}")
    console.print(f"  Bad (crashes):   {bad_version}")
    console.print(f"  Encap:           {encap.name} ({encap.id})")
    console.print()

    versions = get_version_list(good_version, bad_version, console=console)
    if not versions:
        return None

    console.print(f"  Versions to test: {len(versions)}")
    console.print(f"  Bisection steps:  ~{len(versions).bit_length()}")
    console.print()

    # Verify endpoints
    console.print(f"  Testing good version ({good_version})...")
    if test_crash_on_version(crash_file, good_version, encap, console):
        console.print(
            f"  [red]Crash reproduces on 'good' version {good_version}![/red]"
        )
        console.print("  The good version must not crash. Aborting.")
        return None

    console.print(f"  Testing bad version ({bad_version})...")
    if not test_crash_on_version(crash_file, bad_version, encap, console):
        console.print(
            f"  [red]Crash does NOT reproduce on 'bad' version {bad_version}![/red]"
        )
        console.print("  The bad version must crash. Aborting.")
        return None

    # Binary search
    lo = 0  # bad end (newest)
    hi = len(versions) - 1  # good end (oldest)

    while lo + 1 < hi:
        mid = (lo + hi) // 2
        version = versions[mid]

        console.print(f"  [{lo+1}/{len(versions)}] Testing {version}...")
        crashes = test_crash_on_version(crash_file, version, encap, console)

        if crashes:
            console.print(f"    -> Crashes (bad)")
            lo = mid
        else:
            console.print(f"    -> No crash (good)")
            hi = mid

    first_bad = versions[lo]
    last_good = versions[hi] if hi < len(versions) else good_version

    console.print()
    console.print(f"  [bold green]Bisection complete![/bold green]")
    console.print(f"  First bad version:  [bold red]{first_bad}[/bold red]")
    console.print(f"  Last good version:  [bold green]{last_good}[/bold green]")
    console.print()

    return first_bad
