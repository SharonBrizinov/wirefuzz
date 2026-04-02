"""Docker image build and container management via subprocess."""

import subprocess
import sys
from pathlib import Path
from typing import Generator, List, Optional

from rich.console import Console

from wirefuzz.config import CONFIG
from wirefuzz.exceptions import (
    DockerBuildError,
    DockerDaemonError,
    DockerNotFoundError,
    DockerRunError,
)


def _run_docker(args: List[str], capture: bool = True,
                timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    """Run a docker command, raising typed errors on common failures."""
    try:
        result = subprocess.run(
            ["docker"] + args,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return result
    except FileNotFoundError:
        raise DockerNotFoundError()
    except subprocess.TimeoutExpired:
        raise DockerRunError("command timed out")


def check_docker():
    """Verify Docker CLI is available and daemon is running."""
    result = _run_docker(["info"], timeout=10)
    if result.returncode != 0:
        stderr = result.stderr.lower()
        if "not found" in stderr or "not recognized" in stderr:
            raise DockerNotFoundError()
        if "cannot connect" in stderr or "daemon" in stderr:
            raise DockerDaemonError()
        raise DockerRunError(result.stderr.strip())


def image_exists(version: str) -> bool:
    """Check if a wirefuzz Docker image exists for the given version."""
    tag = CONFIG.image_tag(version)
    result = _run_docker(["images", "-q", tag], timeout=10)
    return bool(result.stdout.strip())


def build_image(version: str, no_cache: bool = False, jobs: int = 0,
                verbose: bool = False, console: Console = None):
    """Build fuzzshark Docker image for a Wireshark version.

    Streams build output in real-time. The image is tagged as
    wirefuzz:{version} for caching.
    """
    console = console or Console()
    tag = CONFIG.image_tag(version)
    project_root = Path(__file__).parent.parent

    cmd = [
        "docker", "build",
        "--tag", tag,
        "--build-arg", f"WIRESHARK_VERSION={version}",
        "--build-arg", f"NPROC={jobs}",
    ]

    if no_cache:
        cmd.append("--no-cache")

    cmd.append(str(project_root))

    if verbose:
        console.print(f"[dim]$ {' '.join(cmd)}[/dim]")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        with console.status(
            f"[bold]Building fuzzshark for Wireshark {version}...[/bold]\n"
            f"  Source: {CONFIG.wireshark_repo}\n"
            f"  This may take 15-30 minutes on first build.",
            spinner="dots",
        ):
            output_lines = []
            for line in process.stdout:
                line = line.rstrip()
                output_lines.append(line)
                if verbose:
                    console.print(f"  [dim]{line}[/dim]")

            process.wait()

        if process.returncode != 0:
            tail = "\n".join(output_lines[-20:])
            if "tag not found" in tail.lower() or "not found" in tail.lower():
                raise DockerBuildError(
                    version,
                    f"Version '{version}' not found in Wireshark repository",
                )
            raise DockerBuildError(version, f"exit code {process.returncode}")

        console.print(f"[green]Image built successfully:[/green] {tag}")

    except FileNotFoundError:
        raise DockerNotFoundError()


def run_container(
    version: str,
    env: dict = None,
    volumes: dict = None,
    tmpfs: dict = None,
    container_name: str = None,
    command: str = "fuzz",
    extra_args: List[str] = None,
    verbose: bool = False,
    console: Console = None,
) -> Generator[str, None, None]:
    """Run a wirefuzz container and yield output lines.

    Args:
        version: Wireshark version (image tag).
        env: Dict of environment variables {key: value}.
        volumes: Dict of volume mounts {host_path: container_path}.
        tmpfs: Dict of tmpfs mounts {path: options}.
        container_name: Container name for management.
        command: Entrypoint command (fuzz, build, minimize, reproduce).
        extra_args: Additional arguments passed to entrypoint.
        verbose: Print docker command.
        console: Rich console for output.

    Yields:
        Lines of container output (stdout + stderr merged).
    """
    console = console or Console()
    tag = CONFIG.image_tag(version)

    # Mount entrypoint from host for live development
    project_root = Path(__file__).parent.parent
    entrypoint_host = project_root / "docker" / "entrypoint.sh"

    cmd = ["docker", "run", "--rm"]

    if container_name:
        cmd.extend(["--name", container_name])

    # Environment variables
    if env:
        for key, value in env.items():
            cmd.extend(["-e", f"{key}={value}"])

    # Volume mounts
    if volumes:
        for host_path, container_path in volumes.items():
            cmd.extend(["-v", f"{host_path}:{container_path}"])

    # tmpfs mounts
    if tmpfs:
        for path, options in tmpfs.items():
            cmd.extend(["--tmpfs", f"{path}:{options}"])

    # Mount local entrypoint for live development
    if entrypoint_host.exists():
        cmd.extend([
            "-v", f"{entrypoint_host.resolve()}:/opt/wirefuzz/entrypoint.sh:ro",
            "--entrypoint", "bash",
        ])
        cmd.extend([tag, "/opt/wirefuzz/entrypoint.sh", command])
    else:
        cmd.extend([tag, command])

    if extra_args:
        cmd.extend(extra_args)

    if verbose:
        console.print(f"[dim]$ {' '.join(cmd)}[/dim]")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        for line in process.stdout:
            line = line.rstrip()
            yield line

        process.wait()

        if process.returncode != 0:
            raise DockerRunError(f"container exited with code {process.returncode}")

    except FileNotFoundError:
        raise DockerNotFoundError()
    except KeyboardInterrupt:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        raise


def stop_container(container_name: str, console: Console = None):
    """Stop a running wirefuzz container by name."""
    console = console or Console()
    result = _run_docker(["stop", container_name], timeout=30)
    if result.returncode == 0:
        console.print(f"  [green]Stopped {container_name}[/green]")
    else:
        console.print(f"  [yellow]Container {container_name} not running[/yellow]")


def list_containers(console: Console = None) -> List[dict]:
    """List running wirefuzz containers."""
    result = _run_docker(
        ["ps", "--filter", f"name={CONFIG.docker_image_prefix}_",
         "--format", "{{.Names}}\t{{.Status}}\t{{.RunningFor}}"],
        timeout=10,
    )

    containers = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 3:
            containers.append({
                "name": parts[0],
                "status": parts[1],
                "running_for": parts[2],
            })
    return containers


def list_images(console: Console = None) -> List[dict]:
    """List all wirefuzz Docker images with their tags and sizes."""
    result = _run_docker(
        ["images", CONFIG.docker_image_prefix,
         "--format", "{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}\t{{.ID}}"],
        timeout=10,
    )

    images = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0] != "<none>":
            images.append({
                "tag": parts[0],
                "size": parts[1],
                "created": parts[2],
                "id": parts[3],
            })
    return images


def remove_image(version: str, console: Console = None):
    """Remove a specific wirefuzz Docker image by version tag."""
    console = console or Console()
    tag = CONFIG.image_tag(version)

    if not image_exists(version):
        console.print(f"[yellow]Image {tag} not found.[/yellow]")
        return False

    console.print(f"  Removing {tag}...")
    result = _run_docker(["rmi", "-f", tag], timeout=60)
    if result.returncode != 0:
        console.print(f"  [red]Failed to remove {tag}:[/red] {result.stderr.strip()}")
        return False

    console.print(f"  [green]Removed {tag}[/green]")
    return True


def remove_all_images(console: Console = None):
    """Remove all wirefuzz Docker images."""
    console = console or Console()
    images = list_images()

    if not images:
        console.print("No wirefuzz images found.")
        return

    removed = 0
    for img in images:
        tag = CONFIG.image_tag(img["tag"])
        console.print(f"  Removing {tag} ({img['size']})...")
        result = _run_docker(["rmi", "-f", tag], timeout=60)
        if result.returncode == 0:
            removed += 1
        else:
            console.print(f"  [yellow]Warning:[/yellow] Failed to remove {tag}")

    console.print(f"\n[green]Removed {removed}/{len(images)} image(s).[/green]")
