# IDA Pro MCP Race Condition Detector

A comprehensive toolkit for detecting race conditions, UAF, TOCTOU, and concurrency vulnerabilities in Windows kernel drivers using IDA Pro with MCP (Model Context Protocol) integration.

## Features

- **Automated Race Detection**: Scans drivers for use-after-free, data corruption, and other race conditions
- **TOCTOU Analysis**: Finds Time-of-Check-Time-of-Use vulnerabilities
- **Reference Counting Bugs**: Detects refcount imbalances and double-decrement patterns
- **Rundown Protection Issues**: Finds unchecked ExAcquireRundownProtection calls
- **MCP Integration**: Full API for AI assistant integration (Claude, etc.)
- **CLI Tools**: Command-line interface for scripted analysis

## Components

| File | Description |
|------|-------------|
| `ida_mcp.py` | IDA plugin loader with auto-start MCP server |
| `ida_mcp/` | MCP server implementation package |
| `ida_mcp/api_race.py` | Race detection MCP tools |
| `race_detector.py` | Standalone IDA plugin with HTTP API |
| `ida-mcp-cli.py` | Command-line helper script |

## Installation

### IDA Plugin (MCP Integration)

```bash
# Copy to IDA plugins directory
cp ida_mcp.py "%APPDATA%\Hex-Rays\IDA Pro\plugins\"
cp -r ida_mcp "%APPDATA%\Hex-Rays\IDA Pro\plugins\"
```

### Standalone Plugin

```bash
# Copy to IDA plugins directory
cp race_detector.py "C:\Program Files\IDA Professional 9.0\plugins\"
```

### CLI Tool

```bash
# Copy to your bin directory
cp ida-mcp-cli.py ~/bin/ida-mcp.py
chmod +x ~/bin/ida-mcp.py
```

## Usage

### Quick Start

```bash
# Start IDA with driver
python ida-mcp-cli.py analyze C:\Windows\System32\drivers\target.sys

# Wait for MCP server
python ida-mcp-cli.py wait

# Run race analysis
python ida-mcp-cli.py race-analyze

# List critical issues
python ida-mcp-cli.py race-list -s critical
```

### CLI Commands

```
Race Detection:
  race-analyze          Run full race condition analysis
  race-summary          Get analysis summary
  race-list [-s SEV]    List race candidates (critical/high/medium)
  race-toctou           List TOCTOU vulnerabilities
  race-refcount         List reference counting bugs
  race-rundown          List rundown protection issues
  race-handlers         List dispatch/IOCTL handlers
  race-func <addr>      Analyze specific function
  race-full             Get full results as JSON

General:
  analyze <binary>      Start IDA analysis (GUI)
  wait [timeout]        Wait for MCP server
  functions             List functions
  decompile <addr>      Decompile function
  tools                 List available MCP tools
```

### MCP Tools (API)

Enable race tools with `?ext=race` query parameter:

```
race_analyze           - Run full analysis
race_get_summary       - Get summary
race_get_races         - Get race candidates
race_get_toctou        - Get TOCTOU issues
race_get_refcount      - Get refcount bugs
race_get_rundown       - Get rundown issues
race_get_handlers      - Get dispatch/IOCTL handlers
race_get_globals       - Get shared globals
race_analyze_function  - Analyze single function
race_find_pattern      - Search for API patterns
```

## Detection Patterns

### Use-After-Free Races
- Detects FREE in one function, READ/WRITE in another
- Checks for common lock protection
- Tracks across dispatch handlers

### TOCTOU Vulnerabilities
- ProbeForRead/Write followed by RtlCopyMemory
- Detects double-fetch patterns
- Measures instruction gap between check and use

### Reference Counting
- More decrements than increments
- Potential double-decrement sequences
- Missing references on error paths

### Rundown Protection
- ExAcquireRundownProtection without return check
- Use-after-rundown patterns

## API Example

```python
import requests

# Initialize MCP session
port = 13337
url = f"http://127.0.0.1:{port}/mcp?ext=race"

# Run analysis
response = requests.post(url, json={
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "race_analyze",
        "arguments": {}
    },
    "id": 1
})

results = response.json()
print(f"Found {results['result']['structuredContent']['summary']['critical_races']} critical races")
```

## Output Format

```json
{
  "summary": {
    "total_globals": 15,
    "total_dispatch_handlers": 5,
    "total_ioctl_handlers": 12,
    "critical_races": 2,
    "high_races": 5,
    "toctou_issues": 1,
    "refcount_issues": 3,
    "rundown_issues": 2
  },
  "race_candidates": [
    {
      "severity": "critical",
      "race_type": "use_after_free",
      "reason": "FREE in CleanupHandler vs READ in IoControlHandler",
      "target": "g_DeviceContext",
      "access1": {"address": "0x140005000", "function_name": "CleanupHandler", ...},
      "access2": {"address": "0x140003500", "function_name": "IoControlHandler", ...}
    }
  ]
}
```

## Requirements

- IDA Pro 9.0+ with Hex-Rays decompiler
- Python 3.10+
- Windows (for kernel driver analysis)

## License

MIT
