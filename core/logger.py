"""
Venom OSINT Logger Module
Uses the rich library for beautiful terminal output.
"""

from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.text import Text
import sys

# Define a custom theme
custom_theme = Theme({
    "info": "cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "phase": "bold magenta",
})

class VenomLogger:
    def __init__(self):
        self.console = Console(theme=custom_theme)

    def banner(self) -> None:
        """Prints the Venom ASCII art banner."""
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
            title="[bold yellow]Advanced OSINT Reconnaissance Framework[/bold yellow]",
            subtitle="[cyan]v1.0.0[/cyan]",
            border_style="green"
        )
        self.console.print(panel)
        self.console.print()

    def info(self, message: str) -> None:
        """Logs an informational message."""
        self.console.print(f"[info][*][/info] {message}")

    def success(self, message: str) -> None:
        """Logs a success message."""
        self.console.print(f"[success][+][/success] {message}")

    def warning(self, message: str) -> None:
        """Logs a warning message."""
        self.console.print(f"[warning][!][/warning] {message}")

    def error(self, message: str) -> None:
        """Logs an error message."""
        self.console.print(f"[error][-][/error] {message}")

    def phase_start(self, phase_name: str, description: str) -> None:
        """Logs the start of a scanning phase."""
        self.console.print()
        rule = f"[phase]=== {phase_name} ===[/phase]"
        self.console.rule(rule)
        self.console.print(f"[italic cyan]{description}[/italic cyan]")
        self.console.print()

    def phase_end(self, phase_name: str) -> None:
        """Logs the end of a scanning phase."""
        self.console.print(f"[success]✔ Completed {phase_name}[/success]")
        self.console.print()
