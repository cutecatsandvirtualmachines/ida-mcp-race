"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.

Features:
- Auto-starts MCP server when IDA launches
- Supports dynamic port selection (finds available port if default is in use)
- Writes port info to .ida_mcp_port file for external tool discovery
"""

import sys
import os
import socket
import idaapi
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


def find_available_port(host: str, start_port: int, max_attempts: int = 100) -> int:
    """Find an available port starting from start_port."""
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((host, port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"Could not find available port in range {start_port}-{start_port + max_attempts}")


def write_port_file(port: int, idb_path: str | None = None):
    """Write port info to a discoverable location.

    Creates two files:
    1. ~/.ida_mcp_servers.json - Global registry of all running servers
    2. <idb_path>.mcp_port - Per-database port file (if idb_path provided)
    """
    import json
    import time

    # Global registry file
    global_registry = os.path.expanduser("~/.ida_mcp_servers.json")

    # Read existing registry
    servers = {}
    if os.path.exists(global_registry):
        try:
            with open(global_registry, "r") as f:
                servers = json.load(f)
        except (json.JSONDecodeError, IOError):
            servers = {}

    # Add/update this server entry
    pid = os.getpid()
    servers[str(pid)] = {
        "port": port,
        "pid": pid,
        "idb": idb_path,
        "started": time.time(),
        "url": f"http://127.0.0.1:{port}/mcp"
    }

    # Write back
    try:
        with open(global_registry, "w") as f:
            json.dump(servers, f, indent=2)
    except IOError as e:
        print(f"[MCP] Warning: Could not write global registry: {e}")

    # Per-database port file
    if idb_path:
        port_file = f"{idb_path}.mcp_port"
        try:
            with open(port_file, "w") as f:
                json.dump({"port": port, "pid": pid, "url": f"http://127.0.0.1:{port}/mcp"}, f)
        except IOError as e:
            print(f"[MCP] Warning: Could not write port file: {e}")


def cleanup_port_file(idb_path: str | None = None):
    """Remove port file entries when server stops."""
    import json

    pid = os.getpid()

    # Clean global registry
    global_registry = os.path.expanduser("~/.ida_mcp_servers.json")
    if os.path.exists(global_registry):
        try:
            with open(global_registry, "r") as f:
                servers = json.load(f)
            if str(pid) in servers:
                del servers[str(pid)]
                with open(global_registry, "w") as f:
                    json.dump(servers, f, indent=2)
        except (json.JSONDecodeError, IOError):
            pass

    # Clean per-database port file
    if idb_path:
        port_file = f"{idb_path}.mcp_port"
        if os.path.exists(port_file):
            try:
                os.remove(port_file)
            except IOError:
                pass


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX  # Auto-load on startup
    comment = "MCP Plugin - Auto-starting MCP server"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    HOST = "127.0.0.1"
    BASE_PORT = 13337

    def __init__(self):
        super().__init__()
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.current_port: int | None = None
        self.idb_path: str | None = None

    def init(self):
        # Hook to auto-start server after database is fully loaded
        self._ui_hooks = McpUIHooks(self)
        self._ui_hooks.hook()

        print("[MCP] Plugin loaded, server will start automatically when database is ready")
        print(f"[MCP] Use Edit -> Plugins -> MCP (Ctrl+Alt+M) to restart server")
        return idaapi.PLUGIN_KEEP

    def start_server(self):
        """Start the MCP server with dynamic port selection."""
        if self.mcp:
            self.mcp.stop()
            self.mcp = None

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches, set_download_base_url
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
            from ida_mcp.rpc import set_download_base_url

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        # Find available port
        try:
            port = find_available_port(self.HOST, self.BASE_PORT)
        except RuntimeError as e:
            print(f"[MCP] Error: {e}")
            return

        # Update download base URL for output caching
        set_download_base_url(f"http://{self.HOST}:{port}")

        try:
            MCP_SERVER.serve(
                self.HOST, port, request_handler=IdaMcpHttpRequestHandler
            )
            self.current_port = port
            self.mcp = MCP_SERVER

            # Get IDB path if available
            try:
                import idc
                self.idb_path = idc.get_idb_path()
            except:
                self.idb_path = None

            # Write port file for external discovery
            write_port_file(port, self.idb_path)

            print(f"[MCP] Server started on port {port}")
            print(f"  MCP endpoint: http://{self.HOST}:{port}/mcp")
            print(f"  Config: http://{self.HOST}:{port}/config.html")
            if port != self.BASE_PORT:
                print(f"  (Note: Using alternate port because {self.BASE_PORT} was in use)")

        except OSError as e:
            print(f"[MCP] Error starting server: {e}")

    def run(self, arg):
        """Manual trigger via hotkey or menu - restart server."""
        self.start_server()

    def term(self):
        if self.mcp:
            self.mcp.stop()
            cleanup_port_file(self.idb_path)
        if hasattr(self, '_ui_hooks'):
            self._ui_hooks.unhook()


class McpUIHooks(idaapi.UI_Hooks):
    """UI hooks to auto-start MCP server when database is ready."""

    def __init__(self, plugin: MCP):
        super().__init__()
        self.plugin = plugin
        self._started = False

    def ready_to_run(self):
        """Called when IDA UI is fully initialized and database is loaded."""
        if not self._started:
            self._started = True
            # Use a small delay to ensure everything is fully ready
            idaapi.execute_sync(lambda: self.plugin.start_server(), idaapi.MFF_FAST)


def PLUGIN_ENTRY():
    return MCP()
