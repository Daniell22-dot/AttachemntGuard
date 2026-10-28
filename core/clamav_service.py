from __future__ import annotations

import configparser
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ClamAvResult:
    engine: str
    exit_code: int
    verdict: str
    signature: str | None
    raw_output: str
    timed_out: bool


class ClamAvUnavailable(Exception):
    pass


class ClamAvService:
    def __init__(self, config_path: Path = Path("config.ini")):
        config = configparser.ConfigParser()
        config.read(config_path)

        self.clamdscan_path = config.get(
            "clamav", "clamdscan_path", fallback="clamdscan"
        )
        self.clamscan_path = config.get(
            "clamav", "clamscan_path", fallback="clamscan"
        )
        self.prefer_daemon = config.getboolean(
            "clamav", "prefer_daemon", fallback=True
        )
        self.timeout_seconds = config.getint(
            "clamav", "timeout_seconds", fallback=60
        )
        self.max_file_size = (
            config.getint("clamav", "max_file_size_mb", fallback=25)
            * 1024
            * 1024
        )

    def scan(self, file_path: Path) -> ClamAvResult:
        if not file_path.is_file():
            raise FileNotFoundError(file_path)

        if file_path.stat().st_size > self.max_file_size:
            return ClamAvResult(
                engine="policy",
                exit_code=1,
                verdict="QUARANTINE",
                signature=None,
                raw_output="File exceeds configured ClamAV scan size limit",
                timed_out=False,
            )

        if self.prefer_daemon:
            try:
                return self._run(self.clamdscan_path, file_path, "clamdscan")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

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

        output = (completed.stdout + completed.stderr).strip()
        signature = self._extract_signature(output)

        if completed.returncode == 0:
            verdict = "ALLOW"
        elif completed.returncode == 1:
            verdict = "BLOCK"
        else:
            verdict = "QUARANTINE"

        return ClamAvResult(
            engine=engine,
            exit_code=completed.returncode,
            verdict=verdict,
            signature=signature,
            raw_output=output,
            timed_out=False,
        )

    @staticmethod
    def _extract_signature(output: str) -> str | None:
        for line in output.splitlines():
            if " FOUND" in line:
                return line.split(":")[-1].replace("FOUND", "").strip()

        return None