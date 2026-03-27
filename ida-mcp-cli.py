#!/usr/bin/env python3
"""IDA MCP Helper Script - Interact with IDA Pro MCP servers from command line."""

import sys
import os
import json
import time
import subprocess
import argparse
import urllib.request
import urllib.error

IDA_PATH = r"C:\Program Files\IDA Professional 9.0"
MCP_REGISTRY = os.path.expanduser("~/.ida_mcp_servers.json")

# Colors for terminal (Windows compatible)
class Colors:
    RED = '\033[91m' if os.name != 'nt' or 'WT_SESSION' in os.environ else ''
    GREEN = '\033[92m' if os.name != 'nt' or 'WT_SESSION' in os.environ else ''
    YELLOW = '\033[93m' if os.name != 'nt' or 'WT_SESSION' in os.environ else ''
    BLUE = '\033[94m' if os.name != 'nt' or 'WT_SESSION' in os.environ else ''
    END = '\033[0m' if os.name != 'nt' or 'WT_SESSION' in os.environ else ''


def get_servers():
    """Load server registry."""
    if not os.path.exists(MCP_REGISTRY):
        return {}
    try:
        with open(MCP_REGISTRY) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def get_port(identifier=None):
    """Get port for a server by PID, IDB path, or first available."""
    servers = get_servers()
    if not servers:
        return None

    if identifier is None:
        # Return first available
        first = list(servers.values())[0]
        return first['port']

    # Check if it's a PID
    if identifier in servers:
        return servers[identifier]['port']

    # Check if it's an IDB path
    port_file = f"{identifier}.mcp_port"
    if os.path.exists(port_file):
        try:
            with open(port_file) as f:
                data = json.load(f)
            return data['port']
        except (json.JSONDecodeError, IOError):
            pass

    return None


def mcp_call(method, params=None, port=None):
    """Make an MCP JSON-RPC call."""
    if port is None:
        port = get_port()
    if port is None:
        print(f"{Colors.RED}Error: No IDA MCP server running{Colors.END}", file=sys.stderr)
        return None

    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": 1
    }

    url = f"http://127.0.0.1:{port}/mcp"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.URLError as e:
        print(f"{Colors.RED}Error connecting to MCP server: {e}{Colors.END}", file=sys.stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"{Colors.RED}Error parsing response: {e}{Colors.END}", file=sys.stderr)
        return None


def mcp_tool(tool_name, arguments=None, port=None):
    """Call an MCP tool."""
    return mcp_call("tools/call", {"name": tool_name, "arguments": arguments or {}}, port)


def cmd_servers(args):
    """List running servers."""
    servers = get_servers()
    if not servers:
        print(f"{Colors.YELLOW}No servers registered{Colors.END}")
        return

    print(f"{Colors.BLUE}Running IDA MCP servers:{Colors.END}")
    for pid, info in servers.items():
        idb = info.get('idb', 'N/A')
        print(f"  PID {pid}: port={info['port']} idb={idb}")


def cmd_port(args):
    """Get port for a server."""
    port = get_port(args.identifier)
    if port:
        print(port)
    else:
        print(f"{Colors.RED}No server found{Colors.END}", file=sys.stderr)
        sys.exit(1)


def cmd_tools(args):
    """List available tools."""
    result = mcp_call("tools/list", port=getattr(args, 'port', None))
    if not result:
        return

    tools = result.get('result', {}).get('tools', [])
    for t in tools:
        desc = t.get('description', '')[:60]
        print(f"{t['name']}: {desc}")


def cmd_functions(args):
    """List functions."""
    result = mcp_tool("list_funcs", {"queries": {}}, port=getattr(args, 'port', None))
    if not result:
        return

    sc = result.get('result', {}).get('structuredContent', {})
    data = sc.get('result', [])
    if data and 'data' in data[0]:
        for func in data[0]['data']:
            print(f"{func['addr']} {func['name']} (size: {func['size']})")


def cmd_decompile(args):
    """Decompile a function."""
    result = mcp_tool("decompile", {"addr": args.address}, port=getattr(args, 'port', None))
    if not result:
        return

    sc = result.get('result', {}).get('structuredContent', {})
    if 'code' in sc:
        print(sc['code'])
    else:
        content = result.get('result', {}).get('content', [])
        if content:
            print(content[0].get('text', ''))


def cmd_disasm(args):
    """Disassemble a function."""
    result = mcp_tool("disasm", {"addr": args.address, "max_instructions": args.count}, port=getattr(args, 'port', None))
    if not result:
        return

    print(json.dumps(result.get('result', {}), indent=2))


def cmd_xrefs(args):
    """Get cross-references."""
    result = mcp_tool("xrefs_to", {"addrs": args.address}, port=getattr(args, 'port', None))
    if not result:
        return

    print(json.dumps(result.get('result', {}), indent=2))


def cmd_call(args):
    """Make a raw MCP call."""
    params = json.loads(args.params) if args.params else {}
    result = mcp_call(args.method, params, port=getattr(args, 'port', None))
    if result:
        print(json.dumps(result, indent=2))


def cmd_init(args):
    """Initialize MCP session."""
    result = mcp_call("initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "ida-mcp-cli", "version": "1.0"}
    }, port=getattr(args, 'port', None))
    if result:
        print(json.dumps(result, indent=2))


def cmd_wait(args):
    """Wait for MCP server to be ready."""
    timeout = args.timeout
    elapsed = 0

    print(f"{Colors.YELLOW}Waiting for IDA MCP server...{Colors.END}")
    while elapsed < timeout:
        port = get_port()
        if port:
            try:
                result = mcp_call("ping", {}, port)
                if result:
                    print(f"\n{Colors.GREEN}Server ready on port {port}{Colors.END}")
                    return
            except:
                pass

        time.sleep(1)
        elapsed += 1
        print(f"\r{Colors.YELLOW}Waiting... {elapsed}s/{timeout}s{Colors.END}", end='', flush=True)

    print(f"\n{Colors.RED}Timeout waiting for server{Colors.END}")
    sys.exit(1)


def cmd_analyze(args):
    """Start IDA analysis."""
    binary = os.path.abspath(args.binary)
    ida_exe = os.path.join(IDA_PATH, "ida64.exe")

    if not os.path.exists(ida_exe):
        print(f"{Colors.RED}Error: IDA not found at {ida_exe}{Colors.END}", file=sys.stderr)
        sys.exit(1)

    print(f"{Colors.BLUE}Starting IDA analysis on: {binary}{Colors.END}")
    proc = subprocess.Popen([ida_exe, "-A", binary])
    print(f"{Colors.GREEN}IDA started (PID: {proc.pid}){Colors.END}")
    print("Use 'ida-mcp.py wait' to wait for MCP server")


def cmd_analyze_headless(args):
    """Start headless IDA analysis."""
    binary = os.path.abspath(args.binary)
    ida_exe = os.path.join(IDA_PATH, "idat64.exe")

    if not os.path.exists(ida_exe):
        print(f"{Colors.RED}Error: IDA not found at {ida_exe}{Colors.END}", file=sys.stderr)
        sys.exit(1)

    print(f"{Colors.BLUE}Starting headless IDA analysis on: {binary}{Colors.END}")
    proc = subprocess.Popen([ida_exe, "-A", "-B", binary])
    print(f"{Colors.GREEN}IDA started (PID: {proc.pid}){Colors.END}")


# ============================================================
# Race Detection Commands
# ============================================================

def cmd_race_analyze(args):
    """Run race condition analysis."""
    print(f"{Colors.BLUE}Running race condition analysis...{Colors.END}")
    result = mcp_tool("race_analyze", {}, port=getattr(args, 'port', None))
    if not result:
        return

    sc = result.get('result', {}).get('structuredContent', {})
    summary = sc.get('summary', {})

    print(f"\n{Colors.GREEN}Analysis Complete!{Colors.END}")
    print(f"  Globals found: {summary.get('total_globals', 0)}")
    print(f"  Dispatch handlers: {summary.get('total_dispatch_handlers', 0)}")
    print(f"  IOCTL handlers: {summary.get('total_ioctl_handlers', 0)}")
    print(f"\n{Colors.YELLOW}Vulnerabilities:{Colors.END}")
    print(f"  Critical races: {Colors.RED}{summary.get('critical_races', 0)}{Colors.END}")
    print(f"  High races: {summary.get('high_races', 0)}")
    print(f"  TOCTOU issues: {summary.get('toctou_issues', 0)}")
    print(f"  Refcount issues: {summary.get('refcount_issues', 0)}")
    print(f"  Rundown issues: {summary.get('rundown_issues', 0)}")


def cmd_race_summary(args):
    """Get race analysis summary."""
    result = mcp_tool("race_get_summary", {}, port=getattr(args, 'port', None))
    if not result:
        return
    print(json.dumps(result.get('result', {}).get('structuredContent', {}), indent=2))


def cmd_race_list(args):
    """List race candidates."""
    params = {}
    if args.severity:
        params['severity'] = args.severity

    result = mcp_tool("race_get_races", params, port=getattr(args, 'port', None))
    if not result:
        return

    races = result.get('result', {}).get('structuredContent', [])
    for i, race in enumerate(races, 1):
        sev = race.get('severity', 'unknown')
        color = Colors.RED if sev == 'critical' else Colors.YELLOW
        print(f"\n{color}[{i}] {sev.upper()}: {race.get('race_type', '')}{Colors.END}")
        print(f"    {race.get('reason', '')}")
        print(f"    Target: {race.get('target', '')}")
        a1 = race.get('access1', {})
        a2 = race.get('access2', {})
        print(f"    Access 1: {a1.get('access_type', '')} @ {a1.get('address', '')} in {a1.get('function_name', '')}")
        print(f"    Access 2: {a2.get('access_type', '')} @ {a2.get('address', '')} in {a2.get('function_name', '')}")


def cmd_race_toctou(args):
    """List TOCTOU vulnerabilities."""
    result = mcp_tool("race_get_toctou", {}, port=getattr(args, 'port', None))
    if not result:
        return

    issues = result.get('result', {}).get('structuredContent', [])
    for i, issue in enumerate(issues, 1):
        print(f"\n{Colors.YELLOW}[{i}] TOCTOU in {issue.get('function_name', '')}{Colors.END}")
        print(f"    Check: {issue.get('check_type', '')} @ {issue.get('check_address', '')}")
        print(f"    Use: {issue.get('use_type', '')} @ {issue.get('use_address', '')}")
        print(f"    Gap: {issue.get('gap_instructions', 0)} instructions")


def cmd_race_refcount(args):
    """List refcount issues."""
    result = mcp_tool("race_get_refcount", {}, port=getattr(args, 'port', None))
    if not result:
        return

    issues = result.get('result', {}).get('structuredContent', [])
    for issue in issues:
        print(f"\n{Colors.YELLOW}Refcount issue in {issue.get('function_name', '')}{Colors.END}")
        print(f"    Type: {issue.get('issue_type', '')}")
        print(f"    Increments: {issue.get('increments', 0)}, Decrements: {issue.get('decrements', 0)}")


def cmd_race_rundown(args):
    """List rundown protection issues."""
    result = mcp_tool("race_get_rundown", {}, port=getattr(args, 'port', None))
    if not result:
        return

    issues = result.get('result', {}).get('structuredContent', [])
    for issue in issues:
        print(f"\n{Colors.YELLOW}Rundown issue in {issue.get('function_name', '')}{Colors.END}")
        print(f"    Type: {issue.get('issue_type', '')}")
        print(f"    Address: {issue.get('address', '')}")
        print(f"    Details: {issue.get('details', '')}")


def cmd_race_handlers(args):
    """List dispatch/IOCTL handlers."""
    result = mcp_tool("race_get_handlers", {}, port=getattr(args, 'port', None))
    if not result:
        return

    data = result.get('result', {}).get('structuredContent', {})

    print(f"\n{Colors.BLUE}Dispatch Handlers:{Colors.END}")
    for name, addr in data.get('dispatch_handlers', {}).items():
        print(f"  {name}: {addr}")

    print(f"\n{Colors.BLUE}IOCTL Handlers:{Colors.END}")
    for code, addr in data.get('ioctl_handlers', {}).items():
        print(f"  {code}: {addr}")


def cmd_race_func(args):
    """Analyze a specific function for races."""
    result = mcp_tool("race_analyze_function", {"address": args.address}, port=getattr(args, 'port', None))
    if not result:
        return

    print(json.dumps(result.get('result', {}).get('structuredContent', {}), indent=2))


def cmd_race_full(args):
    """Get full race analysis results."""
    result = mcp_tool("race_get_full_results", {}, port=getattr(args, 'port', None))
    if not result:
        return

    print(json.dumps(result.get('result', {}).get('structuredContent', {}), indent=2))


def main():
    parser = argparse.ArgumentParser(description="IDA MCP Helper Script")
    parser.add_argument('-p', '--port', type=int, help='Connect to specific port instead of auto-detecting')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # servers
    subparsers.add_parser('servers', help='List running IDA MCP servers')

    # port
    p = subparsers.add_parser('port', help='Get port for a specific server')
    p.add_argument('identifier', nargs='?', help='PID or IDB path')

    # tools
    subparsers.add_parser('tools', help='List available MCP tools')

    # functions
    subparsers.add_parser('functions', help='List functions in current binary')

    # decompile
    p = subparsers.add_parser('decompile', help='Decompile function at address')
    p.add_argument('address', help='Function address')

    # disasm
    p = subparsers.add_parser('disasm', help='Disassemble function')
    p.add_argument('address', help='Function address')
    p.add_argument('count', nargs='?', type=int, default=50, help='Number of instructions')

    # xrefs
    p = subparsers.add_parser('xrefs', help='Get cross-references to address')
    p.add_argument('address', help='Address')

    # call
    p = subparsers.add_parser('call', help='Make raw MCP call')
    p.add_argument('method', help='Method name')
    p.add_argument('params', nargs='?', default='{}', help='JSON params')

    # init
    subparsers.add_parser('init', help='Initialize MCP session')

    # wait
    p = subparsers.add_parser('wait', help='Wait for MCP server')
    p.add_argument('timeout', nargs='?', type=int, default=60, help='Timeout in seconds')

    # analyze
    p = subparsers.add_parser('analyze', help='Start IDA analysis (GUI)')
    p.add_argument('binary', help='Binary file path')

    # analyze-headless
    p = subparsers.add_parser('analyze-headless', help='Start headless IDA analysis')
    p.add_argument('binary', help='Binary file path')

    # Race detection commands
    subparsers.add_parser('race-analyze', help='Run race condition analysis')
    subparsers.add_parser('race-summary', help='Get race analysis summary')

    p = subparsers.add_parser('race-list', help='List race candidates')
    p.add_argument('-s', '--severity', choices=['critical', 'high', 'medium'], help='Filter by severity')

    subparsers.add_parser('race-toctou', help='List TOCTOU vulnerabilities')
    subparsers.add_parser('race-refcount', help='List refcount issues')
    subparsers.add_parser('race-rundown', help='List rundown protection issues')
    subparsers.add_parser('race-handlers', help='List dispatch/IOCTL handlers')

    p = subparsers.add_parser('race-func', help='Analyze function for races')
    p.add_argument('address', help='Function address')

    subparsers.add_parser('race-full', help='Get full race analysis results (JSON)')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    commands = {
        'servers': cmd_servers,
        'port': cmd_port,
        'tools': cmd_tools,
        'functions': cmd_functions,
        'decompile': cmd_decompile,
        'disasm': cmd_disasm,
        'xrefs': cmd_xrefs,
        'call': cmd_call,
        'init': cmd_init,
        'wait': cmd_wait,
        'analyze': cmd_analyze,
        'analyze-headless': cmd_analyze_headless,
        'race-analyze': cmd_race_analyze,
        'race-summary': cmd_race_summary,
        'race-list': cmd_race_list,
        'race-toctou': cmd_race_toctou,
        'race-refcount': cmd_race_refcount,
        'race-rundown': cmd_race_rundown,
        'race-handlers': cmd_race_handlers,
        'race-func': cmd_race_func,
        'race-full': cmd_race_full,
    }

    if args.command in commands:
        commands[args.command](args)


if __name__ == '__main__':
    main()
