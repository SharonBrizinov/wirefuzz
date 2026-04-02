"""Typed exception hierarchy for wirefuzz."""


class WirefuzzError(Exception):
    """Base exception for all wirefuzz errors."""


class DockerNotFoundError(WirefuzzError):
    """Docker CLI is not installed or not accessible."""

    def __init__(self):
        super().__init__(
            "Docker is not installed or not in PATH. "
            "Install Docker: https://docs.docker.com/get-docker/"
        )


class DockerDaemonError(WirefuzzError):
    """Docker daemon is not running."""

    def __init__(self):
        super().__init__(
            "Docker daemon is not running. Start Docker and try again."
        )


class DockerBuildError(WirefuzzError):
    """Docker image build failed."""

    def __init__(self, version: str, detail: str = ""):
        msg = f"Failed to build wirefuzz image for Wireshark {version}"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)
        self.version = version


class DockerRunError(WirefuzzError):
    """Docker container execution failed."""

    def __init__(self, detail: str = ""):
        msg = "Container execution failed"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class VersionNotFoundError(WirefuzzError):
    """Specified Wireshark version/tag does not exist."""

    def __init__(self, version: str):
        super().__init__(
            f"Wireshark version '{version}' not found. "
            "Run 'wirefuzz versions' to see available versions."
        )
        self.version = version


class NoPcapsFoundError(WirefuzzError):
    """No pcap files found at the specified path."""

    def __init__(self, path: str):
        super().__init__(
            f"No .pcap, .pcapng, or .cap files found at '{path}'"
        )
        self.path = path


class EncapNotFoundError(WirefuzzError):
    """Specified encapsulation type not found."""

    def __init__(self, encap: str):
        super().__init__(
            f"Encapsulation type '{encap}' not found. "
            "Use 'wirefuzz encaps' to list available types."
        )
        self.encap = encap


class FuzzerError(WirefuzzError):
    """Fuzzer execution error."""

    def __init__(self, detail: str = ""):
        msg = "Fuzzer error"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class GitLabApiError(WirefuzzError):
    """Failed to reach GitLab API."""

    def __init__(self, detail: str = ""):
        msg = "Cannot reach GitLab API"
        if detail:
            msg += f": {detail}"
        msg += ". Use --version to specify a version manually."
        super().__init__(msg)
