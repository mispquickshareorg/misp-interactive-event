"""Interactive prompts for creating a MISP DDoS event."""

import logging
import re
from datetime import datetime
from typing import List, Optional

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.panel import Panel

from misp_client import MISPClient, MISPValidationError, MISPConnectionError

logger = logging.getLogger(__name__)
console = Console()


def _validate_ip(ip: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def _validate_date(date_str: str) -> bool:
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
        try:
            datetime.strptime(date_str.strip(), fmt)
            return True
        except ValueError:
            continue
    return False


def _validate_tls_fingerprint(fp_type: str, fp_value: str) -> bool:
    if not fp_value:
        return False
    fp_type = fp_type.lower()
    fp_value = fp_value.strip()
    if fp_type in ("ja3", "ja3s"):
        return bool(re.match(r'^[a-fA-F0-9]{32}$', fp_value))
    if fp_type.startswith("ja4"):
        return bool(re.match(r'^[a-zA-Z0-9_]{10,50}$', fp_value))
    if fp_type == "jarm":
        return bool(re.match(r'^[a-fA-F0-9]{62}$', fp_value))
    if fp_type in ("hassh", "hasshserver"):
        return bool(re.match(r'^[a-fA-F0-9]{32}$', fp_value))
    return bool(re.match(r'^[a-zA-Z0-9_\-:]+$', fp_value))


def _ask(message: str, validator, error: str, default: Optional[str] = None, allow_empty: bool = False) -> str:
    while True:
        value = Prompt.ask(message, default=default)
        if allow_empty and not value:
            return value
        if not value:
            console.print("[red]Input cannot be empty[/red]")
            continue
        if validator(value):
            return value
        console.print(f"[red]{error}[/red]")


def prompt_event_details() -> dict:
    console.print("\n[bold]Event Information[/bold]\n")

    event_name = _ask(
        "[cyan]Event name[/cyan]",
        lambda x: 0 < len(x.strip()) <= 255,
        "Event name must be 1-255 characters",
    )

    console.print("\n[dim]Date format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS[/dim]")
    event_date = _ask(
        "[cyan]Event date[/cyan]",
        _validate_date,
        "Invalid date. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS",
        default=datetime.now().strftime("%Y-%m-%d"),
    )

    annotation_text = _ask(
        "[cyan]Annotation text[/cyan]",
        lambda x: 0 < len(x.strip()) <= 5000,
        "Annotation must be 1-5000 characters",
    )

    # Attacker IPs
    console.print("\n[bold]Attacker IPs[/bold]")
    console.print("[dim]Enter attacker/source IPs. Press Enter with no value when done.[/dim]\n")
    attacker_ips: List[str] = []
    while True:
        ip = _ask(
            f"[cyan]Attacker IP #{len(attacker_ips) + 1}[/cyan]",
            lambda x: not x or _validate_ip(x),
            "Invalid IP address",
            allow_empty=True,
        )
        if not ip:
            if not attacker_ips:
                console.print("[yellow]At least one attacker IP is required[/yellow]")
                continue
            break
        attacker_ips.append(ip)
        console.print(f"[green]Added {ip}[/green]")
        if len(attacker_ips) >= 1000:
            break

    # Destination IPs (optional)
    console.print("\n[bold]Destination IPs[/bold] [dim](optional - press Enter to skip)[/dim]")
    destination_ips: List[str] = []
    while True:
        ip = _ask(
            f"[cyan]Destination IP #{len(destination_ips) + 1}[/cyan] [dim](Enter to finish)[/dim]",
            lambda x: not x or _validate_ip(x),
            "Invalid IP address",
            allow_empty=True,
        )
        if not ip:
            break
        destination_ips.append(ip)
        console.print(f"[green]Added {ip}[/green]")
        if len(destination_ips) >= 1000:
            break

    # TLP
    console.print("\n[bold]TLP Level[/bold]")
    console.print("  1. [green]clear[/green]   2. [green]green[/green] (default)   3. [yellow]amber[/yellow]   4. [red]red[/red]\n")
    tlp_map = {"1": "clear", "2": "green", "3": "amber", "4": "red"}
    tlp_choice = _ask(
        "[cyan]Select TLP (1-4)[/cyan]",
        lambda x: x in tlp_map,
        "Enter 1, 2, 3, or 4",
        default="2",
    )
    tlp = tlp_map[tlp_choice]

    # TLS Fingerprints (optional)
    console.print("\n[bold]TLS Fingerprints[/bold] [dim](optional)[/dim]")
    console.print("[dim]Supported: ja3, ja3s, ja4, ja4s, ja4h, ja4x, ja4t, ja4ts, ja4ssh, jarm, hassh, hasshserver[/dim]")
    console.print("[dim]Type the algorithm name to add, or press Enter to skip.[/dim]\n")
    valid_fp_types = set(
        ["ja3", "ja3s", "ja4", "ja4s", "ja4h", "ja4x", "ja4t", "ja4ts", "ja4ssh", "jarm", "hassh", "hasshserver"]
    )
    tls_fingerprints: dict = {}
    while True:
        fp_type = Prompt.ask("[cyan]Fingerprint type[/cyan] [dim](Enter to skip)[/dim]", default="").strip().lower()
        if not fp_type:
            break
        if fp_type not in valid_fp_types:
            console.print(f"[red]Unknown type '{fp_type}'. Valid: {', '.join(sorted(valid_fp_types))}[/red]")
            continue
        fps = tls_fingerprints.get(fp_type, [])
        while True:
            val = Prompt.ask(f"[cyan]{fp_type.upper()} #{len(fps) + 1}[/cyan] [dim](Enter to finish)[/dim]", default="")
            if not val:
                break
            if _validate_tls_fingerprint(fp_type, val):
                fps.append(val)
                console.print("[green]Added[/green]")
            else:
                console.print(f"[red]Invalid {fp_type.upper()} format[/red]")
        if fps:
            tls_fingerprints[fp_type] = fps

    return {
        "event_name": event_name,
        "event_date": event_date,
        "annotation_text": annotation_text,
        "attacker_ips": attacker_ips,
        "destination_ips": destination_ips if destination_ips else None,
        "destination_ports": None,
        "tlp": tlp,
        "tls_fingerprints": tls_fingerprints if tls_fingerprints else None,
    }


def display_summary(event_data: dict) -> None:
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("Event Name", event_data["event_name"])
    table.add_row("Date", event_data["event_date"])
    table.add_row("Attacker IPs", str(len(event_data["attacker_ips"])))
    if event_data.get("destination_ips"):
        table.add_row("Destination IPs", str(len(event_data["destination_ips"])))
    table.add_row("TLP", event_data["tlp"])
    ann = event_data["annotation_text"]
    table.add_row("Annotation", ann[:100] + "..." if len(ann) > 100 else ann)
    if event_data.get("tls_fingerprints"):
        fp_summary = ", ".join(f"{k.upper()}: {len(v)}" for k, v in event_data["tls_fingerprints"].items())
        table.add_row("TLS Fingerprints", fp_summary)
    console.print("\n[bold]Event Summary[/bold]\n")
    console.print(table)


def run(misp_client: MISPClient) -> Optional[dict]:
    try:
        console.print(Panel("[bold cyan]MISP DDoS Event Creator[/bold cyan]\nInteractive mode", border_style="cyan"))
        event_data = prompt_event_details()
        display_summary(event_data)
        console.print()
        if not Confirm.ask("[bold cyan]Submit this event to MISP?[/bold cyan]", default=True):
            console.print("[yellow]Cancelled[/yellow]")
            return None

        console.print("\n[cyan]Creating event in MISP...[/cyan]")
        result = misp_client.create_ddos_event(**event_data)

        console.print("\n[bold green]Event created successfully![/bold green]")
        console.print(f"  Event ID:  {result['event_id']}")
        console.print(f"  UUID:      {result['event_uuid']}")
        console.print(f"  URL:       {result['url']}")
        return result

    except MISPValidationError as e:
        console.print(f"\n[red]Validation error: {e}[/red]")
        return None
    except MISPConnectionError as e:
        console.print(f"\n[red]Connection error: {e}[/red]")
        return None
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")
        return None
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {e}[/red]")
        logger.exception("Unexpected error")
        return None
