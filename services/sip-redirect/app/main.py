"""VVP SIP Redirect Service.

Sprint 42: AsyncIO entrypoint for SIP redirect signing service.
Sprint 47: Added monitoring dashboard.
"""

import asyncio
import logging
import signal
import sys

from app.config import LOG_LEVEL, validate_config, STATUS_ADMIN_KEY, MONITOR_ENABLED
from app.redirect.handler import handle_invite, get_rate_limiter
from app.redirect.client import close_issuer_client
from app.sip.transport import run_servers
from app.status import start_status_server, stop_status_server

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("vvp-sip")


async def main() -> None:
    """Main entry point for SIP redirect service."""
    log.info("Starting VVP SIP Redirect Service...")

    # Validate configuration
    issues = validate_config()
    if issues:
        for issue in issues:
            log.error(f"Configuration error: {issue}")
        sys.exit(1)

    # Start SIP servers
    servers = await run_servers(handle_invite)
    if not servers:
        log.error("No servers started - check VVP_SIP_TRANSPORT configuration")
        sys.exit(1)

    # Start status HTTP server (if admin key configured)
    status_handler = None
    if STATUS_ADMIN_KEY:
        status_handler = await start_status_server(get_rate_limiter)
    else:
        log.info("Status endpoint disabled (VVP_STATUS_ADMIN_KEY not set)")

    # Start monitoring dashboard (if enabled)
    dashboard_started = False
    if MONITOR_ENABLED:
        try:
            from app.monitor import start_dashboard_server
            dashboard_started = await start_dashboard_server()
        except ImportError as e:
            log.warning(f"Dashboard disabled - aiohttp not installed: {e}")
        except Exception as e:
            log.error(f"Failed to start dashboard: {e}")
    else:
        log.info("Monitoring dashboard disabled (VVP_MONITOR_ENABLED not set)")

    log.info("VVP SIP Redirect Service started")

    # Set up signal handlers for graceful shutdown
    stop_event = asyncio.Event()

    def handle_signal(sig: signal.Signals) -> None:
        log.info(f"Received {sig.name}, shutting down...")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda s=sig: handle_signal(s))

    # Wait for shutdown signal
    await stop_event.wait()

    # Cleanup
    log.info("Stopping servers...")

    # Stop monitoring dashboard
    if dashboard_started:
        try:
            from app.monitor import stop_dashboard_server
            await stop_dashboard_server()
        except Exception as e:
            log.warning(f"Error stopping dashboard: {e}")

    # Stop status HTTP server
    if status_handler:
        await stop_status_server()

    # Stop SIP servers
    for server in servers:
        if hasattr(server, "close"):
            server.close()
            if hasattr(server, "wait_closed"):
                await server.wait_closed()
        elif hasattr(server, "abort"):
            server.abort()

    await close_issuer_client()
    log.info("VVP SIP Redirect Service stopped")


def run() -> None:
    """Run the service."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run()
