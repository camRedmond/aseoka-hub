"""ASEOKA Hub CLI - Command line interface for the ASEOKA hub server."""

import os
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

app = typer.Typer(
    name="aseoka-hub",
    help="ASEOKA Hub - Central coordination server for ASEOKA agents",
    no_args_is_help=True,
)

console = Console()


def version_callback(value: bool):
    """Print version and exit."""
    if value:
        rprint("[bold blue]ASEOKA Hub[/bold blue] version [green]1.0.0[/green]")
        raise typer.Exit()


@app.callback()
def callback(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
):
    """ASEOKA Hub - Central coordination server CLI."""
    pass


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind to"),
    db_path: str = typer.Option(
        "hub.db", "--db", help="Path to the database file"
    ),
    log_level: str = typer.Option(
        "INFO", "--log-level", "-l", help="Log level (DEBUG, INFO, WARNING, ERROR)"
    ),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload for development"),
):
    """Start the ASEOKA hub server."""
    import uvicorn
    from aseoka_hub.server import app as hub_app

    console.print(Panel.fit(
        f"[bold blue]ASEOKA Hub Server[/bold blue]\n\n"
        f"Host: [green]{host}[/green]\n"
        f"Port: [green]{port}[/green]\n"
        f"Database: [green]{db_path}[/green]",
        title="Starting Hub",
    ))

    uvicorn.run(
        hub_app,
        host=host,
        port=port,
        log_level=log_level.lower(),
        reload=reload,
    )


@app.command()
def status(
    hub_url: str = typer.Option(
        "http://localhost:8000", "--url", "-u", help="Hub server URL"
    ),
):
    """Check the status of the hub server."""
    import httpx

    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(f"{hub_url}/health")
            health = resp.json()

        table = Table(title="Hub Status")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Status", health.get("status", "unknown"))
        table.add_row("Version", health.get("version", "unknown"))
        table.add_row("Timestamp", health.get("timestamp", "unknown"))

        console.print(table)

    except httpx.ConnectError:
        console.print(f"[red]Error:[/red] Could not connect to hub at {hub_url}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def agents(
    hub_url: str = typer.Option(
        "http://localhost:8000", "--url", "-u", help="Hub server URL"
    ),
    client_id: Optional[str] = typer.Option(
        None, "--client", "-c", help="Filter by client ID"
    ),
    status_filter: Optional[str] = typer.Option(
        None, "--status", "-s", help="Filter by status (online/offline)"
    ),
):
    """List registered agents."""
    import httpx

    try:
        params = {}
        if client_id:
            params["client_id"] = client_id
        if status_filter:
            params["status"] = status_filter

        with httpx.Client(timeout=5.0) as client:
            resp = client.get(f"{hub_url}/agents", params=params)
            agents_data = resp.json()

        if not agents_data:
            console.print("[yellow]No agents registered.[/yellow]")
            return

        table = Table(title="Registered Agents")
        table.add_column("Agent ID", style="dim")
        table.add_column("Site", style="cyan")
        table.add_column("Platform", style="blue")
        table.add_column("Status", style="green")
        table.add_column("Health", style="yellow")
        table.add_column("Last Heartbeat", style="dim")

        for agent in agents_data:
            status_val = agent.get("status", "unknown")
            status_color = "green" if status_val == "online" else "red"

            health = agent.get("health_score", 0)
            health_color = "green" if health >= 70 else "yellow" if health >= 50 else "red"

            table.add_row(
                agent.get("agent_id", "")[:16],
                agent.get("site_name", agent.get("site_url", ""))[:30],
                agent.get("platform", "N/A") or "N/A",
                f"[{status_color}]{status_val}[/{status_color}]",
                f"[{health_color}]{health}[/{health_color}]",
                (agent.get("last_heartbeat") or "Never")[:19],
            )

        console.print(table)
        console.print(f"\n[dim]Total: {len(agents_data)} agent(s)[/dim]")

    except httpx.ConnectError:
        console.print(f"[red]Error:[/red] Could not connect to hub at {hub_url}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def clients(
    hub_url: str = typer.Option(
        "http://localhost:8000", "--url", "-u", help="Hub server URL"
    ),
):
    """List registered clients."""
    import httpx

    # Note: The hub API doesn't have a list clients endpoint yet
    # This is a placeholder that would need API support
    console.print("[yellow]Client listing requires API endpoint /clients (not implemented yet)[/yellow]")
    console.print("\nTo get a specific client, use:")
    console.print("  [cyan]curl http://localhost:8000/clients/<client_id>[/cyan]")


@app.command()
def create_client(
    name: str = typer.Argument(..., help="Client name"),
    hub_url: str = typer.Option(
        "http://localhost:8000", "--url", "-u", help="Hub server URL"
    ),
    tier: str = typer.Option(
        "starter", "--tier", "-t", help="Client tier (starter, pro, enterprise)"
    ),
    email: Optional[str] = typer.Option(
        None, "--email", "-e", help="Contact email"
    ),
):
    """Create a new client."""
    import httpx

    try:
        payload = {
            "client_name": name,
            "tier": tier,
        }
        if email:
            payload["contact_email"] = email

        with httpx.Client(timeout=5.0) as client:
            resp = client.post(f"{hub_url}/clients", json=payload)

            if resp.status_code == 201:
                data = resp.json()
                console.print(Panel.fit(
                    f"[bold green]Client Created Successfully[/bold green]\n\n"
                    f"Client ID: [cyan]{data.get('client_id')}[/cyan]\n"
                    f"Name: [white]{data.get('client_name')}[/white]\n"
                    f"Tier: [blue]{data.get('tier')}[/blue]\n"
                    f"Max Agents: [yellow]{data.get('max_agents')}[/yellow]\n"
                    f"Max Pages/Scan: [yellow]{data.get('max_pages_per_scan')}[/yellow]",
                    title="New Client",
                ))
            else:
                console.print(f"[red]Error:[/red] {resp.json().get('detail', 'Unknown error')}")
                raise typer.Exit(1)

    except httpx.ConnectError:
        console.print(f"[red]Error:[/red] Could not connect to hub at {hub_url}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def activities(
    hub_url: str = typer.Option(
        "http://localhost:8000", "--url", "-u", help="Hub server URL"
    ),
    agent_id: Optional[str] = typer.Option(
        None, "--agent", "-a", help="Filter by agent ID"
    ),
    activity_type: Optional[str] = typer.Option(
        None, "--type", "-t", help="Filter by activity type"
    ),
    limit: int = typer.Option(20, "--limit", "-l", help="Maximum number of activities"),
):
    """List recent activities."""
    import httpx

    try:
        params = {"limit": limit}
        if agent_id:
            params["agent_id"] = agent_id
        if activity_type:
            params["activity_type"] = activity_type

        with httpx.Client(timeout=5.0) as client:
            resp = client.get(f"{hub_url}/activities", params=params)
            activities_data = resp.json()

        if not activities_data:
            console.print("[yellow]No activities found.[/yellow]")
            return

        table = Table(title="Recent Activities")
        table.add_column("Time", style="dim")
        table.add_column("Agent", style="cyan")
        table.add_column("Type", style="blue")
        table.add_column("Description", style="white")

        for activity in activities_data:
            created = activity.get("created_at", "")[:19] if activity.get("created_at") else "N/A"

            table.add_row(
                created,
                (activity.get("agent_id") or "")[:12],
                activity.get("activity_type", ""),
                (activity.get("description") or "")[:50],
            )

        console.print(table)

    except httpx.ConnectError:
        console.print(f"[red]Error:[/red] Could not connect to hub at {hub_url}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def playbook(
    hub_url: str = typer.Option(
        "http://localhost:8000", "--url", "-u", help="Hub server URL"
    ),
    issue_type: Optional[str] = typer.Option(
        None, "--type", "-t", help="Filter by issue type"
    ),
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Filter by category"
    ),
):
    """List playbook entries."""
    import httpx

    try:
        params = {}
        if issue_type:
            params["issue_type"] = issue_type
        if category:
            params["category"] = category

        with httpx.Client(timeout=5.0) as client:
            resp = client.get(f"{hub_url}/playbook", params=params)

            if resp.status_code == 404:
                console.print("[yellow]Playbook endpoint not available.[/yellow]")
                return

            data = resp.json()
            entries = data.get("entries", []) if isinstance(data, dict) else data

        if not entries:
            console.print("[yellow]No playbook entries found.[/yellow]")
            return

        table = Table(title="Playbook Entries")
        table.add_column("ID", style="dim")
        table.add_column("Issue Type", style="cyan")
        table.add_column("Category", style="blue")
        table.add_column("Severity", style="red")
        table.add_column("Success Rate", style="green")

        for entry in entries:
            severity = entry.get("severity", "")
            severity_color = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "green",
            }.get(severity, "white")

            success_rate = entry.get("success_rate", 0)
            rate_color = "green" if success_rate >= 70 else "yellow" if success_rate >= 50 else "red"

            table.add_row(
                entry.get("entry_id", "")[:12],
                entry.get("issue_type", ""),
                entry.get("category", ""),
                f"[{severity_color}]{severity}[/{severity_color}]",
                f"[{rate_color}]{success_rate:.0f}%[/{rate_color}]",
            )

        console.print(table)

    except httpx.ConnectError:
        console.print(f"[red]Error:[/red] Could not connect to hub at {hub_url}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def create_token(
    client_id: str = typer.Argument(..., help="Client ID to create token for"),
    hub_url: str = typer.Option(
        "http://localhost:8000", "--url", "-u", help="Hub server URL"
    ),
    tier: str = typer.Option(
        "starter", "--tier", "-t", help="Client tier"
    ),
    max_agents: int = typer.Option(
        1, "--max-agents", "-m", help="Maximum agents this token can create"
    ),
    expires_hours: int = typer.Option(
        24, "--expires", "-e", help="Token expiry in hours"
    ),
):
    """Create a provisioning token for agent installation."""
    import httpx

    try:
        payload = {
            "client_id": client_id,
            "tier": tier,
            "max_agents": max_agents,
            "expires_hours": expires_hours,
        }

        with httpx.Client(timeout=5.0) as client:
            resp = client.post(f"{hub_url}/admin/provisioning-tokens", json=payload)

            if resp.status_code == 201:
                data = resp.json()
                console.print(Panel.fit(
                    f"[bold green]Provisioning Token Created[/bold green]\n\n"
                    f"Token: [cyan]{data.get('token')}[/cyan]\n"
                    f"Client ID: [white]{data.get('client_id')}[/white]\n"
                    f"Tier: [blue]{data.get('tier')}[/blue]\n"
                    f"Max Agents: [yellow]{data.get('max_agents')}[/yellow]\n"
                    f"Expires: [dim]{data.get('expires_at')}[/dim]\n\n"
                    f"[yellow]Save this token! It will only be shown once.[/yellow]",
                    title="New Token",
                ))

                # Print install command
                token = data.get('token')
                console.print(f"\n[bold]Installation command:[/bold]")
                console.print(f"[dim]curl -sSL {hub_url}/install.sh?token={token} | bash -s -- <site_url> <site_name>[/dim]")
            else:
                console.print(f"[red]Error:[/red] {resp.json().get('detail', 'Unknown error')}")
                raise typer.Exit(1)

    except httpx.ConnectError:
        console.print(f"[red]Error:[/red] Could not connect to hub at {hub_url}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


def main():
    """Entry point for the hub CLI."""
    app()


if __name__ == "__main__":
    main()
