from __future__ import annotations

import configparser
import os
import shutil
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path

DEFAULT_CONFIG_PATH = Path("config.ini")


@dataclass(frozen=True)
class ClamAvConfig:
    enabled: bool = False
    clamdscan_path: str = "clamdscan"
    clamscan_path: str = "clamscan"
    prefer_daemon: bool = True
    timeout_seconds: int = 60
    max_file_size_mb: int = 25


@dataclass(frozen=True)
class ClamAvResult:
    engine: str
    exit_code: int
    verdict: str
    signature: str | None
    raw_output: str
    timed_out: bool
    error: str | None = None


class ClamAvUnavailable(Exception):
    pass


def load_clamav_config(config_path: Path | None = None) -> ClamAvConfig:
    path = config_path if config_path is not None else DEFAULT_CONFIG_PATH
    config = configparser.ConfigParser()
    config.read(path)

    return ClamAvConfig(
        enabled=config.getboolean("clamav", "enabled", fallback=False),
        clamdscan_path=config.get("clamav", "clamdscan_path", fallback="clamdscan"),
        clamscan_path=config.get("clamav", "clamscan_path", fallback="clamscan"),
        prefer_daemon=config.getboolean("clamav", "prefer_daemon", fallback=True),
        timeout_seconds=config.getint("clamav", "timeout_seconds", fallback=60),
        max_file_size_mb=config.getint("clamav", "max_file_size_mb", fallback=25),
    )


def resolve_executable(configured: str, executable_name: str) -> str:
    candidate = (configured or "").strip()
    if candidate:
        located = shutil.which(candidate)
        if located:
            return located
        direct = Path(candidate).expanduser()
        if direct.is_file():
            return str(direct.resolve())

    located = shutil.which(executable_name)
    if located:
        return located

    roots = []
    for variable in ("ProgramFiles", "ProgramFiles(x86)"):
        value = os.environ.get(variable)
        if value:
            roots.append(Path(value))
    roots.extend((Path("C:/Program Files"), Path("C:/Program Files (x86)")))

    for root in roots:
        for directory in ("ClamAV", "clamav"):
            executable = root / directory / f"{executable_name}.exe"
            if executable.is_file():
                return str(executable)

    return candidate or executable_name


def build_clamav_service(
    config_path: Path | None = None,
    enabled: bool | None = None,
) -> ClamAvService | None:
    config = load_clamav_config(config_path)
    if enabled is not None:
        config = replace(config, enabled=enabled)
    if not config.enabled:
        return None

    return ClamAvService(
        replace(
            config,
            clamdscan_path=resolve_executable(config.clamdscan_path, "clamdscan"),
            clamscan_path=resolve_executable(config.clamscan_path, "clamscan"),
        )
    )


class ClamAvService:
    def __init__(self, config: ClamAvConfig | None = None):
        self.config = config or load_clamav_config()
        self.clamdscan_path = self.config.clamdscan_path
        self.clamscan_path = self.config.clamscan_path
        self.prefer_daemon = self.config.prefer_daemon
        self.timeout_seconds = self.config.timeout_seconds
        self.max_file_size = self.config.max_file_size_mb * 1024 * 1024

    def scan(self, file_path: Path) -> ClamAvResult:
        file_path = Path(file_path)
        if not file_path.is_file():
            raise FileNotFoundError(file_path)

        if file_path.stat().st_size > self.max_file_size:
            message = "File exceeds configured ClamAV scan size limit"
            return ClamAvResult(
                engine="policy",
                exit_code=1,
                verdict="QUARANTINE",
                signature=None,
                raw_output=message,
                timed_out=False,
                error=message,
            )

        if self.prefer_daemon:
            try:
                daemon_result = self._run(self.clamdscan_path, file_path, "clamdscan")
            except (ClamAvUnavailable, subprocess.TimeoutExpired):
                daemon_result = None
            if daemon_result is not None and not self._daemon_unreachable(daemon_result):
                return daemon_result

        return self._run(self.clamscan_path, file_path, "clamscan")

    def _run(
        self,
        executable: str,
        file_path: Path,
        engine: str,
    ) -> ClamAvResult:
        command = [executable, "--no-summary", str(file_path)]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ClamAvUnavailable(
                f"ClamAV executable not found: {executable}"
            ) from exc
        except subprocess.TimeoutExpired:
            return ClamAvResult(
                engine=engine,
                exit_code=2,
                verdict="QUARANTINE",
                signature=None,
                raw_output="",
                timed_out=True,
                error="ClamAV scan timed out",
            )
        except OSError as exc:
            raise ClamAvUnavailable(
                f"Could not start ClamAV: {executable} ({type(exc).__name__})"
            ) from exc

        output = (completed.stdout + completed.stderr).strip()
        signature = self._extract_signature(output)

        if completed.returncode == 0:
            verdict = "ALLOW"
        elif completed.returncode == 1:
            verdict = "BLOCK"
        else:
            verdict = "QUARANTINE"

        error = None
        if verdict == "QUARANTINE":
            error = self._classify_error(output)

        return ClamAvResult(
            engine=engine,
            exit_code=completed.returncode,
            verdict=verdict,
            signature=signature,
            raw_output=output,
            timed_out=False,
            error=error,
        )

    @staticmethod
    def _daemon_unreachable(result: ClamAvResult) -> bool:
        if result.verdict != "QUARANTINE":
            return False
        lowered = result.raw_output.lower()
        return any(
            marker in lowered
            for marker in ("clamd", "could not connect", "connection refused")
        )

    @staticmethod
    def _extract_signature(output: str) -> str | None:
        for line in output.splitlines():
            if " FOUND" in line:
                return line.split(":")[-1].replace("FOUND", "").strip()
        return None

    @staticmethod
    def _classify_error(output: str) -> str:
        lowered = output.lower()
        if "database" in lowered and any(
            marker in lowered
            for marker in ("no such file", "not found", "missing", "can't get file status")
        ):
            return (
                "ClamAV signatures are missing; run freshclam to update "
                "the virus database"
            )
        return "ClamAV scanner error or inconclusive result"
