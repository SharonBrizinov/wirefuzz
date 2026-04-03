"""CLI definition using Click."""

import sys
from pathlib import Path

import click
from rich.console import Console

from wirefuzz import __version__
from wirefuzz.config import CONFIG
from wirefuzz.exceptions import WirefuzzError

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="wirefuzz")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging.")
@click.pass_context
def main(ctx, verbose):
    """wirefuzz - Wireshark protocol dissector fuzzing tool.

    Build fuzzshark inside Docker with libfuzzer + sanitizers,
    extract corpus by encapsulation type, and fuzz dissectors.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["console"] = console


# ---- build ----

@main.command()
@click.argument("ws_version", required=False, default=None)
@click.option("-j", "--jobs", "nproc", type=int, default=0,
              help="Parallel build jobs (0 = auto).")
@click.option("--no-cache", is_flag=True, help="Force rebuild without cache.")
@click.pass_context
def build(ctx, ws_version, nproc, no_cache):
    """Build fuzzshark Docker image for a Wireshark version.

    If VERSION is omitted, shows an interactive picker.

    \b
    Examples:
      wirefuzz build master
      wirefuzz build v4.6.4
      wirefuzz build               # interactive picker
    """
    from wirefuzz.docker import build_image, check_docker
    from wirefuzz.versions import select_version_interactive, validate_version

    try:
        check_docker()

        if ws_version:
            version, is_known = validate_version(ws_version)
            if not is_known:
                console.print(
                    f"  [yellow]Warning:[/yellow] Version '{version}' not found "
                    "in GitLab tags (proceeding anyway)"
                )
        else:
            version = select_version_interactive(console=console)

        console.print(f"\n  Building fuzzshark for [bold]{version}[/bold]...")
        build_image(
            version, no_cache=no_cache, jobs=nproc,
            verbose=ctx.obj["verbose"],
            console=console,
        )
    except WirefuzzError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)


# ---- clean ----

@main.command()
@click.argument("ws_version", required=False, default=None)
@click.option("--all", "clean_all", is_flag=True,
              help="Remove ALL wirefuzz Docker images.")
@click.pass_context
def clean(ctx, ws_version, clean_all):
    """Remove wirefuzz Docker image(s).

    \b
    Examples:
      wirefuzz clean v4.6.4        Remove a specific version
      wirefuzz clean master         Remove master image
      wirefuzz clean --all          Remove all wirefuzz images
    """
    from wirefuzz.docker import list_images, remove_all_images, remove_image

    try:
        if clean_all:
            remove_all_images(console=console)
        elif ws_version:
            remove_image(ws_version, console=console)
        else:
            images = list_images()
            if not images:
                console.print("No wirefuzz images found.")
                return
            console.print("\n[bold]Cached wirefuzz images:[/bold]\n")
            for img in images:
                console.print(f"  {img['tag']:20s} {img['size']:>10s}   {img['created']}")
            console.print(
                "\n[dim]Use 'wirefuzz clean <version>' or 'wirefuzz clean --all'[/dim]\n"
            )
    except WirefuzzError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# ---- versions ----

@main.command(name="versions")
@click.option("--all", "show_all", is_flag=True,
              help="Show all versions including RCs.")
@click.option("--refresh", is_flag=True,
              help="Force refresh from GitLab API.")
@click.pass_context
def versions_cmd(ctx, show_all, refresh):
    """List available Wireshark versions."""
    from wirefuzz.versions import list_versions

    try:
        list_versions(
            show_all=show_all,
            refresh=refresh,
            console=console,
        )
    except WirefuzzError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# ---- encaps ----

@main.command(name="encaps")
@click.option("--all", "show_all", is_flag=True,
              help="Show all encapsulation types (default: common only).")
@click.pass_context
def encaps_cmd(ctx, show_all):
    """List available encapsulation types."""
    from wirefuzz.encaps import display_encaps

    display_encaps(common_only=not show_all, console=console)


# ---- fuzz ----

@main.command()
@click.option("-V", "--version", "ws_version", default=None,
              help="Wireshark version (tag, branch, or commit).")
@click.option("-p", "--pcap", "pcap_path", default=None,
              type=click.Path(exists=True),
              help="PCAP file or directory with seed corpus.")
@click.option("-e", "--encap", "encap_str", default=None,
              help="Encapsulation type (ID or name, e.g. '1' or 'ETHERNET').")
@click.option("-w", "--workers", type=int, default=0,
              help="Number of libfuzzer fork workers (default: 4).")
@click.option("-o", "--output", "output_dir", default=None,
              type=click.Path(),
              help=f"Output base directory (default: ./{CONFIG.default_output_dir}/).")
@click.option("-t", "--timeout", type=int, default=None,
              help=f"Per-input timeout in ms (default: {CONFIG.default_timeout_ms}).")
@click.option("--rss-limit", type=int, default=None,
              help=f"RSS limit per worker in MB (default: {CONFIG.default_rss_limit_mb}).")
@click.option("--max-len", type=int, default=None,
              help=f"Max input length (default: {CONFIG.default_max_len}).")
@click.option("--dict", "dict_path", default=None,
              type=click.Path(exists=True),
              help="Path to libfuzzer dictionary file.")
@click.option("--duration", default=None,
              help="Max fuzzing duration (e.g. '2h', '30m', 'forever').")
@click.option("--mount-source", default=None,
              type=click.Path(exists=True),
              help="Mount Wireshark source from host (for incremental builds).")
@click.option("--resume", "resume_dir", default=None,
              type=click.Path(exists=True),
              help="Resume a previous run directory.")
@click.option("--auto-encap", is_flag=True,
              help="Auto-detect encap type from pcap majority (requires -p).")
@click.option("--no-cache", is_flag=True,
              help="Force rebuild Docker image before fuzzing.")
@click.pass_context
def fuzz(ctx, ws_version, pcap_path, encap_str, workers, output_dir,
         timeout, rss_limit, max_len, dict_path, duration,
         mount_source, resume_dir, auto_encap, no_cache):
    """Start a fuzzing session.

    Extracts packets matching the target encap type from seed PCAPs,
    then launches fuzzshark in Docker with libfuzzer to find crashes.

    If options are omitted, shows interactive pickers.

    \b
    Examples:
      wirefuzz fuzz -V master -p ./pcaps/ -e 1 -w 16
      wirefuzz fuzz -V master -p ./pcaps/ --auto-encap
      wirefuzz fuzz --resume ./wirefuzz_runs/ethernet_1_master_20260401_143022/
      wirefuzz fuzz                          # fully interactive
    """
    from wirefuzz.docker import build_image, check_docker, image_exists
    from wirefuzz.encaps import (
        EncapType,
        get_encap,
        pick_encap_interactive,
    )
    from wirefuzz.fuzzer import resume_session, start_fuzz_session
    from wirefuzz.versions import select_version_interactive, validate_version

    try:
        check_docker()

        # Resume mode
        if resume_dir:
            resume_session(
                Path(resume_dir),
                verbose=ctx.obj["verbose"],
                console=console,
            )
            return

        # Version selection
        if ws_version:
            version, is_known = validate_version(ws_version)
            if not is_known:
                console.print(
                    f"  [yellow]Warning:[/yellow] Version '{version}' not found "
                    "in GitLab tags (proceeding anyway)"
                )
        else:
            version = select_version_interactive(console=console)

        # Encap selection
        if encap_str:
            encap = get_encap(encap_str)
            if encap is None:
                console.print(f"[red]Error:[/red] Unknown encap type '{encap_str}'")
                console.print("[dim]Use 'wirefuzz encaps' to list available types.[/dim]")
                sys.exit(1)
        else:
            if auto_encap and not pcap_path:
                console.print("[red]Error:[/red] --auto-encap requires -p/--pcap")
                sys.exit(1)

            dist = None
            # If pcap(s) were provided, probe them first and show what's inside
            if pcap_path:
                from wirefuzz.corpus import find_pcap_files, probe_encaps
                from wirefuzz.encaps import ENCAP_REGISTRY, _build_wtap_to_dlt
                from rich.table import Table as RichTable

                pcap_files = find_pcap_files(Path(pcap_path).resolve())
                if pcap_files:
                    console.print(f"\n  Probing {len(pcap_files)} pcap file(s) (first 1000 packets)...")
                    dist = probe_encaps(pcap_files, max_packets=1000)
                    if dist:
                        wtap_to_dlt = _build_wtap_to_dlt()
                        table = RichTable(show_header=True, header_style="bold", box=None, padding=(0, 2))
                        table.add_column("WTAP", justify="right", style="cyan")
                        table.add_column("DLT", justify="right", style="dim")
                        table.add_column("Name")
                        table.add_column("Full name", style="dim")
                        table.add_column("Packets", justify="right", style="green")
                        total_probed = sum(dist.values())
                        for wtap_id, count in dist.items():
                            e = ENCAP_REGISTRY.get(wtap_id)
                            name = e.name if e else "unknown"
                            full = e.full_name if e else ""
                            dlt = wtap_to_dlt.get(wtap_id)
                            dlt_str = str(dlt) if dlt is not None else "—"
                            pct = count / total_probed * 100
                            table.add_row(str(wtap_id), dlt_str, name, full, f"{count} ({pct:.0f}%)")
                        console.print()
                        console.print(table)
                        console.print()

            # Auto-detect: pick the majority encap from the probe
            if auto_encap and dist:
                top_wtap_id = next(iter(dist))  # first key = highest count
                encap = ENCAP_REGISTRY.get(top_wtap_id)
                if encap is None:
                    console.print(f"[red]Error:[/red] Auto-detected encap WTAP {top_wtap_id} not in registry")
                    sys.exit(1)
                top_count = dist[top_wtap_id]
                total_probed = sum(dist.values())
                pct = top_count / total_probed * 100
                console.print(
                    f"  [bold green]Auto-detected:[/bold green] {encap.name} (WTAP {encap.id}) "
                    f"— {top_count}/{total_probed} packets ({pct:.0f}%)"
                )
            elif auto_encap and not dist:
                console.print("[red]Error:[/red] --auto-encap: no packets found in pcap files")
                sys.exit(1)
            else:
                encap = pick_encap_interactive(console=console)

        console.print(f"\n  Encap: [bold]{encap.name}[/bold] ({encap.id}) - {encap.full_name}")

        # Ensure image is built
        if not image_exists(version):
            console.print(f"\n  Image not found for {version}, building...")
            build_image(version, no_cache=no_cache,
                        verbose=ctx.obj["verbose"], console=console)

        # Output directory
        if output_dir is None:
            output_dir = CONFIG.default_output_dir
        output_base = Path(output_dir).resolve()
        output_base.mkdir(parents=True, exist_ok=True)

        # Corpus preparation
        if pcap_path:
            from wirefuzz.corpus import extract_by_encap, find_pcap_files

            pcap_p = Path(pcap_path).resolve()
            pcap_files = find_pcap_files(pcap_p)

            if pcap_files:
                console.print(f"\n  Found {len(pcap_files)} pcap file(s)")
                console.print(f"  Extracting packets for encap {encap.name} ({encap.id})...")

                # Create a temporary corpus directory for extraction
                import tempfile
                with tempfile.TemporaryDirectory(prefix="wirefuzz_corpus_") as tmp:
                    tmp_corpus = Path(tmp)
                    stats = extract_by_encap(
                        pcap_paths=pcap_files,
                        target_encap=encap,
                        output_dir=tmp_corpus,
                        console=console,
                    )

                    console.print(f"  Total packets: {stats.total_packets}")
                    console.print(f"  Matched:       {stats.matched_packets}")
                    console.print(f"  Unique:        {stats.unique_packets}")

                    if stats.unique_packets == 0:
                        console.print(
                            f"\n[yellow]Warning:[/yellow] No packets found with encap "
                            f"{encap.name} ({encap.id}). Starting with empty corpus."
                        )
                        if stats.encap_distribution:
                            console.print("  Encap types found in input:")
                            from wirefuzz.encaps import ENCAP_REGISTRY
                            for eid, count in sorted(
                                stats.encap_distribution.items(),
                                key=lambda x: -x[1]
                            ):
                                ename = ENCAP_REGISTRY.get(eid)
                                label = f"{ename.name} ({eid})" if ename else f"unknown ({eid})"
                                console.print(f"    {label}: {count} packets")

                    corpus_dir = tmp_corpus
                    # Start fuzzing (corpus will be copied to run dir)
                    start_fuzz_session(
                        version=version,
                        encap=encap,
                        corpus_dir=corpus_dir,
                        output_base=output_base,
                        workers=workers,
                        max_len=max_len,
                        timeout_ms=timeout,
                        rss_limit_mb=rss_limit,
                        duration=duration,
                        dict_path=Path(dict_path) if dict_path else None,
                        mount_source=Path(mount_source) if mount_source else None,
                        pcap_source=pcap_p,
                        samples_before_min=stats.matched_packets,
                        samples_after_min=stats.unique_packets,
                        verbose=ctx.obj["verbose"],
                        console=console,
                    )
            else:
                # pcap_path exists but no pcap files - use as raw corpus
                start_fuzz_session(
                    version=version,
                    encap=encap,
                    corpus_dir=pcap_p,
                    output_base=output_base,
                    workers=workers,
                    max_len=max_len,
                    timeout_ms=timeout,
                    rss_limit_mb=rss_limit,
                    duration=duration,
                    dict_path=Path(dict_path) if dict_path else None,
                    mount_source=Path(mount_source) if mount_source else None,
                    pcap_source=pcap_p,
                    samples_before_min=0,
                    samples_after_min=sum(1 for f in pcap_p.iterdir() if f.is_file()) if pcap_p.is_dir() else 1,
                    verbose=ctx.obj["verbose"],
                    console=console,
                )
        else:
            # No pcap path - start with empty corpus
            import tempfile
            with tempfile.TemporaryDirectory(prefix="wirefuzz_empty_") as tmp:
                start_fuzz_session(
                    version=version,
                    encap=encap,
                    corpus_dir=Path(tmp),
                    output_base=output_base,
                    workers=workers,
                    max_len=max_len,
                    timeout_ms=timeout,
                    rss_limit_mb=rss_limit,
                    duration=duration,
                    dict_path=Path(dict_path) if dict_path else None,
                    mount_source=Path(mount_source) if mount_source else None,
                    pcap_source=None,
                    samples_before_min=0,
                    samples_after_min=0,
                    verbose=ctx.obj["verbose"],
                    console=console,
                )

    except WirefuzzError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)


# ---- corpus ----

@main.group()
@click.pass_context
def corpus(ctx):
    """Corpus management commands."""
    pass


@corpus.command(name="prepare")
@click.option("-p", "--pcap", "pcap_path", required=True,
              type=click.Path(exists=True),
              help="PCAP file or directory.")
@click.option("-e", "--encap", "encap_str", default=None,
              help="Encapsulation type (ID or name).")
@click.option("-o", "--output", "output_dir", required=True,
              type=click.Path(),
              help="Output directory for raw corpus files.")
@click.pass_context
def corpus_prepare(ctx, pcap_path, encap_str, output_dir):
    """Extract packets by encap type from PCAPs into raw corpus files.

    \b
    Examples:
      wirefuzz corpus prepare -p ./pcaps/ -e 1 -o ./corpus_ethernet/
      wirefuzz corpus prepare -p capture.pcapng -e ETHERNET -o ./corpus/
    """
    from wirefuzz.corpus import extract_by_encap, find_pcap_files
    from wirefuzz.encaps import get_encap, pick_encap_interactive

    try:
        # Encap selection
        if encap_str:
            encap = get_encap(encap_str)
            if encap is None:
                console.print(f"[red]Error:[/red] Unknown encap '{encap_str}'")
                sys.exit(1)
        else:
            encap = pick_encap_interactive(console=console)

        pcap_files = find_pcap_files(Path(pcap_path))
        if not pcap_files:
            console.print(f"[red]Error:[/red] No pcap files found at '{pcap_path}'")
            sys.exit(1)

        console.print(f"\n  Files: {len(pcap_files)}")
        console.print(f"  Encap: {encap.name} ({encap.id}) - {encap.full_name}")
        console.print()

        stats = extract_by_encap(
            pcap_paths=pcap_files,
            target_encap=encap,
            output_dir=Path(output_dir),
            console=console,
        )

        console.print(f"\n  [bold]Results:[/bold]")
        console.print(f"    Total packets:   {stats.total_packets}")
        console.print(f"    Matched:         {stats.matched_packets}")
        console.print(f"    Unique:          {stats.unique_packets}")
        console.print(f"    Skipped:         {stats.skipped_packets}")
        console.print(f"    Output:          {output_dir}")

        if stats.encap_distribution:
            console.print(f"\n  [bold]Encap distribution:[/bold]")
            from wirefuzz.encaps import ENCAP_REGISTRY
            for eid, count in sorted(
                stats.encap_distribution.items(), key=lambda x: -x[1]
            ):
                ename = ENCAP_REGISTRY.get(eid)
                label = f"{ename.name} ({eid})" if ename else f"unknown ({eid})"
                marker = " <-- target" if eid == encap.id else ""
                console.print(f"    {label}: {count}{marker}")

        console.print()

    except WirefuzzError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@corpus.command(name="merge_pcap")
@click.option("-p", "--pcap", "pcap_path", required=True,
              type=click.Path(exists=True),
              help="PCAP file or directory to merge from.")
@click.option("-e", "--encap", "encap_str", default=None,
              help="Encapsulation type to extract (ID or name). Interactive if omitted.")
@click.option("-o", "--output", "output_path", required=True,
              type=click.Path(),
              help="Output .pcapng file path.")
@click.pass_context
def corpus_merge_pcap(ctx, pcap_path, encap_str, output_path):
    """Merge matching packets from PCAPs into a single pcapng file.

    Extracts packets of the given encap type, deduplicates by SHA-256,
    and writes them into one pcapng file. Useful for building a clean
    merged corpus for sharing or further processing.

    \b
    Examples:
      wirefuzz corpus merge_pcap -p ./pcaps/ -e 33 -o docsis_merged.pcapng
      wirefuzz corpus merge_pcap -p ./pcaps/ -o merged.pcapng   # interactive encap picker
    """
    from wirefuzz.corpus import extract_by_encap, find_pcap_files, probe_encaps, write_pcapng
    from wirefuzz.encaps import ENCAP_REGISTRY, _build_wtap_to_dlt, get_encap, pick_encap_interactive
    from rich.table import Table as RichTable
    import tempfile

    try:
        input_path = Path(pcap_path).resolve()
        pcap_files = find_pcap_files(input_path)

        if not pcap_files:
            console.print(f"[red]Error:[/red] No pcap files found at '{pcap_path}'")
            sys.exit(1)

        # Encap selection
        if encap_str:
            encap = get_encap(encap_str)
            if encap is None:
                console.print(f"[red]Error:[/red] Unknown encap '{encap_str}'")
                sys.exit(1)
        else:
            # Probe pcaps first
            console.print(f"\n  Probing {len(pcap_files)} pcap file(s) (first 1000 packets)...")
            dist = probe_encaps(pcap_files, max_packets=1000)
            if dist:
                wtap_to_dlt = _build_wtap_to_dlt()
                table = RichTable(show_header=True, header_style="bold", box=None, padding=(0, 2))
                table.add_column("WTAP", justify="right", style="cyan")
                table.add_column("DLT", justify="right", style="dim")
                table.add_column("Name")
                table.add_column("Full name", style="dim")
                table.add_column("Packets", justify="right", style="green")
                total_probed = sum(dist.values())
                for wtap_id, count in dist.items():
                    e = ENCAP_REGISTRY.get(wtap_id)
                    dlt = wtap_to_dlt.get(wtap_id)
                    table.add_row(
                        str(wtap_id),
                        str(dlt) if dlt is not None else "—",
                        e.name if e else "unknown",
                        e.full_name if e else "",
                        f"{count} ({count / total_probed * 100:.0f}%)",
                    )
                console.print()
                console.print(table)
                console.print()
            encap = pick_encap_interactive(console=console)

        console.print(f"\n  Encap: [bold]{encap.name}[/bold] (WTAP {encap.id}) - {encap.full_name}")
        console.print(f"  Files: {len(pcap_files)}")
        with tempfile.TemporaryDirectory(prefix="wirefuzz_merge_") as tmp:
            stats = extract_by_encap(
                pcap_paths=pcap_files,
                target_encap=encap,
                output_dir=Path(tmp),
                console=console,
            )
            if stats.unique_packets == 0:
                console.print(f"\n[yellow]Warning:[/yellow] No packets matched encap {encap.name} ({encap.id}).")
                sys.exit(0)
            payloads = [f.read_bytes() for f in sorted(Path(tmp).iterdir()) if f.is_file()]
            out = Path(output_path)
            written = write_pcapng(payloads, encap.id, out)
        console.print(f"\n  [bold]Results:[/bold]")
        console.print(f"    Total packets:   {stats.total_packets}")
        console.print(f"    Matched:         {stats.matched_packets}")
        console.print(f"    Unique:          {stats.unique_packets}")
        console.print(f"    Written:         {written} packets → {output_path}")
        console.print()

    except WirefuzzError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@corpus.command(name="merge_seed")
@click.option("-d", "--dir", "seed_dir", required=True,
              type=click.Path(exists=True),
              help="Directory containing raw seed/corpus files.")
@click.option("-e", "--encap", "encap_str", default=None,
              help="Encapsulation type (ID or name). Interactive if omitted.")
@click.option("-o", "--output", "output_path", required=True,
              type=click.Path(),
              help="Output .pcapng file path.")
@click.pass_context
def corpus_merge_seed(ctx, seed_dir, encap_str, output_path):
    """Merge raw seed/corpus files into a single pcapng file.

    Reads raw payload files (e.g. from a fuzzer corpus directory),
    wraps each one as a packet with the given encap header, and writes
    them into one pcapng file.

    \b
    Examples:
      wirefuzz corpus merge_seed -d ./corpus/ -e 33 -o docsis_merged.pcapng
      wirefuzz corpus merge_seed -d ./corpus/ -o merged.pcapng   # interactive encap picker
    """
    from wirefuzz.corpus import write_pcapng
    from wirefuzz.encaps import get_encap, pick_encap_interactive

    try:
        input_path = Path(seed_dir).resolve()
        if not input_path.is_dir():
            console.print(f"[red]Error:[/red] '{seed_dir}' is not a directory")
            sys.exit(1)

        raw_files = sorted(f for f in input_path.rglob("*") if f.is_file())
        if not raw_files:
            console.print(f"[red]Error:[/red] No files found in '{seed_dir}'")
            sys.exit(1)

        # Encap selection
        if encap_str:
            encap = get_encap(encap_str)
            if encap is None:
                console.print(f"[red]Error:[/red] Unknown encap '{encap_str}'")
                sys.exit(1)
        else:
            console.print(f"\n  [dim]Raw corpus directory — encap type needed to write pcapng header.[/dim]")
            encap = pick_encap_interactive(console=console)

        console.print(f"\n  Encap: [bold]{encap.name}[/bold] (WTAP {encap.id}) - {encap.full_name}")
        console.print(f"  Source: raw corpus ({len(raw_files)} files)")
        payloads = [f.read_bytes() for f in raw_files if f.stat().st_size > 0]
        out = Path(output_path)
        written = write_pcapng(payloads, encap.id, out)
        console.print(f"\n  [bold]Results:[/bold]")
        console.print(f"    Files read:  {len(raw_files)}")
        console.print(f"    Written:     {written} packets → {output_path}")
        console.print()

    except WirefuzzError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# ---- status ----

@main.command()
@click.argument("run_dir", required=False, default=None,
                type=click.Path(exists=True))
@click.pass_context
def status(ctx, run_dir):
    """Show status of fuzz runs.

    If RUN_DIR is given, shows live stats for that run.
    Otherwise, lists all runs.
    """
    try:
        if run_dir:
            from wirefuzz.monitor import display_live_stats
            display_live_stats(Path(run_dir), console=console)
        else:
            from wirefuzz.dashboard import display_runs
            output_base = Path(CONFIG.default_output_dir)
            display_runs(output_base, console=console)
    except WirefuzzError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        pass


# ---- crashes ----

@main.command(name="crashes")
@click.argument("run_dir", type=click.Path(exists=True))
@click.option("--reproduce", "reproduce_file", default=None,
              type=click.Path(exists=True),
              help="Reproduce a specific crash file.")
@click.pass_context
def crashes_cmd(ctx, run_dir, reproduce_file):
    """List and triage crashes from a fuzz run.

    \b
    Examples:
      wirefuzz crashes ./wirefuzz_runs/ethernet_1_master_20260401_143022/
    """
    from wirefuzz.crashes import display_crashes
    try:
        display_crashes(Path(run_dir), console=console)
    except WirefuzzError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# ---- stop ----

@main.command()
@click.argument("run_dir", required=False, default=None,
                type=click.Path(exists=True))
@click.option("--all", "stop_all", is_flag=True,
              help="Stop all running wirefuzz containers.")
@click.pass_context
def stop(ctx, run_dir, stop_all):
    """Stop running fuzz session(s).

    \b
    Examples:
      wirefuzz stop ./wirefuzz_runs/ethernet_1_master_20260401_143022/
      wirefuzz stop --all
    """
    from wirefuzz.docker import list_containers, stop_container
    from wirefuzz.fuzzer import stop_session

    try:
        if stop_all:
            containers = list_containers()
            if not containers:
                console.print("No running wirefuzz containers.")
                return
            for c in containers:
                stop_container(c["name"], console=console)
        elif run_dir:
            stop_session(Path(run_dir), console=console)
        else:
            console.print("[dim]Use 'wirefuzz stop <run_dir>' or 'wirefuzz stop --all'[/dim]")
    except WirefuzzError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
