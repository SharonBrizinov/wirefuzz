"""Configuration defaults and constants."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class WirefuzzConfig:
    # Wireshark source
    wireshark_repo: str = "https://gitlab.com/wireshark/wireshark.git"
    gitlab_api: str = "https://gitlab.com/api/v4/projects/wireshark%2Fwireshark"

    # Docker
    docker_image_prefix: str = "wirefuzz"
    tmpfs_size: str = "4G"

    # Fuzzer defaults
    default_max_len: int = 65535
    default_timeout_ms: int = 5000
    default_rss_limit_mb: int = 4096
    default_workers: int = 4

    # Pcap file extensions to scan
    pcap_extensions: list = field(
        default_factory=lambda: [".pcap", ".pcapng", ".cap"]
    )

    # Cache
    cache_dir: Path = field(
        default_factory=lambda: Path.home() / ".cache" / "wirefuzz"
    )
    tag_cache_ttl_seconds: int = 3600  # 1 hour

    # Output
    default_output_dir: str = "wirefuzz_runs"

    def image_tag(self, version: str) -> str:
        """Return full Docker image tag for a Wireshark version."""
        return f"{self.docker_image_prefix}:{version}"


# Global singleton
CONFIG = WirefuzzConfig()
