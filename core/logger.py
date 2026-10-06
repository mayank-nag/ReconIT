"""
Venom OSINT Framework Logger Module.
Provides formatted terminal logging via rich and optional structured file logging.
"""

import sys
import logging
import traceback
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.text import Text

custom_theme = Theme({
    "info": "cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "phase": "bold magenta",
    "debug": "dim white",
})


class VenomLogger:
    """Enhanced logger with console styling, log levels, and optional file output."""

    def __init__(self, verbose: bool = False, log_file: Optional[str] = None):
        self.console = Console(theme=custom_theme)
        self.verbose = verbose
        self.log_file = Path(log_file) if log_file else None

        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self._write_file(f"=== ReconIT / Venom OSINT Log Started {datetime.now(timezone.utc).isoformat()} ===\n")

    def _write_file(self, line: str) -> None:
        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass

    def _log_record(self, level: str, message: str) -> None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        self._write_file(f"[{timestamp}] [{level.upper()}] {message}")

    def banner(self) -> None:
        """Prints the ReconIT / Venom ASCII art banner."""
        ascii_art = r"""
 __      __  ______   _   _    ___    __  __ 
 \ \    / / |  ____| | \ | |  / _ \  |  \/  |
  \ \  / /  | |__    |  \| | | | | | | \  / |
   \ \/ /   |  __|   | . ` | | | | | | |\/| |
    \  /    | |____  | |\  | | |_| | | |  | |
     \/     |______| |_| \_|  \___/  |_|  |_|
        """
        panel = Panel(
            Text(ascii_art, style="bold green", justify="center"),
            title="[bold yellow]ReconIT — Venom OSINT Framework[/bold yellow]",
            subtitle="[cyan]v1.0.0 • Low-Impact Reconnaissance Engine[/cyan]",
            border_style="green",
        )
        self.console.print(panel)
        self.console.print()

    def info(self, message: str) -> None:
        """Logs an informational message."""
        self._log_record("INFO", message)
        self.console.print(f"[info][*][/info] {message}")

    def success(self, message: str) -> None:
        """Logs a success message."""
        self._log_record("SUCCESS", message)
        self.console.print(f"[success][+][/success] {message}")

    def warning(self, message: str) -> None:
        """Logs a warning message."""
        self._log_record("WARNING", message)
        self.console.print(f"[warning][!][/warning] {message}")

    def error(self, message: str) -> None:
        """Logs an error message."""
        self._log_record("ERROR", message)
        self.console.print(f"[error][-][/error] {message}")

    def debug(self, message: str) -> None:
        """Logs a debug message (visible only when verbose mode is active)."""
        self._log_record("DEBUG", message)
        if self.verbose:
            self.console.print(f"[debug][DBG][/debug] {message}")

    def exception(self, message: str, exc: Optional[BaseException] = None) -> None:
        """Logs an exception with traceback in debug mode or log file."""
        err_msg = f"{message}: {exc}" if exc else message
        self.error(err_msg)
        tb_str = traceback.format_exc() if exc or sys.exc_info()[0] else ""
        if tb_str:
            self._write_file(f"Traceback:\n{tb_str}")
            if self.verbose:
                self.console.print(f"[dim red]{tb_str}[/dim red]")

    def phase_start(self, phase_name: str, description: str) -> None:
        """Logs the start of a scanning phase."""
        self._log_record("PHASE", f"Starting {phase_name}: {description}")
        self.console.print()
        rule = f"[phase]=== {phase_name} ===[/phase]"
        self.console.rule(rule)
        self.console.print(f"[italic cyan]{description}[/italic cyan]")
        self.console.print()

    def phase_end(self, phase_name: str) -> None:
        """Logs the end of a scanning phase."""
        self._log_record("PHASE", f"Completed {phase_name}")
        self.console.print(f"[success]✔ Completed {phase_name}[/success]")
        self.console.print()
