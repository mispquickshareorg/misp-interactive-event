#!/usr/bin/env python3
"""Create a DDoS event in MISP using interactive prompts."""

import sys
import os
import logging
from typing import Optional

import click
from dotenv import load_dotenv
from rich.console import Console

from misp_client import MISPClient, MISPConnectionError

console = Console()


def load_config(env_file: Optional[str] = None):
    if env_file:
        load_dotenv(env_file)
    else:
        load_dotenv()

    url = os.environ.get("MISP_URL", "").strip()
    api_key = os.environ.get("MISP_API_KEY", "").strip()
    verify_ssl = os.environ.get("MISP_VERIFY_SSL", "true").strip().lower() not in ("false", "0", "no", "off")
    try:
        timeout = int(os.environ.get("MISP_TIMEOUT", "30").strip())
    except ValueError:
        timeout = 30

    if not url:
        console.print("[red]ERROR: MISP_URL is not set. Copy .env.example to .env.[/red]")
        sys.exit(1)
    if not api_key:
        console.print("[red]ERROR: MISP_API_KEY is not set.[/red]")
        sys.exit(1)

    return url.rstrip("/"), api_key, verify_ssl, timeout


@click.command()
@click.option("--env-file", type=click.Path(exists=True), help="Path to .env file")
@click.option("--debug", is_flag=True, help="Enable debug logging")
def main(env_file: Optional[str], debug: bool):
    """Create a DDoS event in MISP using interactive prompts."""
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    url, api_key, verify_ssl, timeout = load_config(env_file)

    try:
        misp_client = MISPClient(url=url, api_key=api_key, verify_ssl=verify_ssl, timeout=timeout)
    except MISPConnectionError as e:
        console.print(f"[red]Connection failed: {e}[/red]")
        console.print("  Check MISP_URL, MISP_API_KEY, and network settings.")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Initialization error: {e}[/red]")
        sys.exit(1)

    import interactive_cli
    result = interactive_cli.run(misp_client)
    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
