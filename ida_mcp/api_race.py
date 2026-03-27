"""IDA MCP Race Condition Detection API

Provides tools for detecting race conditions, TOCTOU, UAF, and other
concurrency vulnerabilities in Windows kernel drivers.

Tools:
- race_analyze: Run full race condition analysis
- race_get_results: Get analysis results
- race_get_summary: Get analysis summary
- race_find_handlers: Find IRP dispatch and IOCTL handlers
- race_find_globals: Find shared global variables
- race_find_toctou: Find Time-of-Check-Time-of-Use patterns
- race_find_refcount: Find reference counting bugs
- race_find_rundown: Find rundown protection issues
- race_find_uaf: Find potential Use-After-Free races
- race_analyze_function: Analyze specific function for races
"""

import idaapi
import idautils
import idc
import ida_funcs
import ida_segment
import ida_xref
import ida_nalt

from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any

from .rpc import tool, ext
from .sync import idasync

# ============================================================
# Configuration - Windows Kernel API Patterns
# ============================================================

FREE_FUNCTIONS = [
    "ExFreePool", "ExFreePoolWithTag", "ExFreeToNPagedLookasideList",
    "ExFreeToPagedLookasideList", "IoFreeMdl", "IoFreeIrp", "IoFreeWorkItem",
    "ObfDereferenceObject", "ObDereferenceObject", "ObDereferenceObjectDeferDelete",
    "MmFreeContiguousMemory", "MmFreeNonCachedMemory", "MmFreePagesFromMdl",
    "ExDeleteNPagedLookasideList", "ExDeletePagedLookasideList",
    "NdisFreeMemory", "NdisFreeNetBufferList", "NdisFreePacket",
    "WdfObjectDelete", "WdfObjectDereference"
]

ALLOC_FUNCTIONS = [
    "ExAllocatePool", "ExAllocatePoolWithTag", "ExAllocatePool2",
    "ExAllocatePool3", "ExAllocatePoolZero", "ExAllocatePoolQuotaZero",
    "ExAllocateFromNPagedLookasideList", "ExAllocateFromPagedLookasideList",
    "IoAllocateMdl", "IoAllocateIrp", "IoAllocateWorkItem",
    "ObfReferenceObject", "ObReferenceObject", "ObReferenceObjectByHandle",
    "ObReferenceObjectByPointer", "MmAllocateContiguousMemory",
    "MmAllocateNonCachedMemory", "MmAllocatePagesForMdl",
    "NdisAllocateMemory", "NdisAllocateNetBufferList", "NdisAllocatePacket",
    "WdfObjectCreate", "WdfObjectReference"
]

LOCK_ACQUIRE_FUNCTIONS = [
    "KeAcquireSpinLock", "KeAcquireSpinLockAtDpcLevel", "KeAcquireSpinLockRaiseToDpc",
    "KeTryToAcquireSpinLockAtDpcLevel", "KeAcquireInStackQueuedSpinLock",
    "KeAcquireInStackQueuedSpinLockAtDpcLevel",
    "ExAcquireFastMutex", "ExAcquireFastMutexUnsafe", "ExTryToAcquireFastMutex",
    "ExAcquireResourceExclusiveLite", "ExAcquireResourceSharedLite",
    "ExAcquireSharedStarveExclusive", "ExAcquireSharedWaitForExclusive",
    "ExAcquireRundownProtection", "ExAcquireRundownProtectionEx",
    "ExAcquireRundownProtectionCacheAware", "ExAcquireRundownProtectionCacheAwareEx",
    "KeWaitForSingleObject", "KeWaitForMultipleObjects", "KeWaitForMutexObject",
    "ExAcquirePushLockExclusive", "ExAcquirePushLockShared",
    "FltAcquirePushLockExclusive", "FltAcquirePushLockShared",
    "KeEnterCriticalRegion", "KeEnterGuardedRegion",
    "FsRtlEnterFileSystem", "IoAcquireCancelSpinLock", "IoAcquireRemoveLock"
]

LOCK_RELEASE_FUNCTIONS = [
    "KeReleaseSpinLock", "KeReleaseSpinLockFromDpcLevel",
    "KeReleaseInStackQueuedSpinLock", "KeReleaseInStackQueuedSpinLockFromDpcLevel",
    "ExReleaseFastMutex", "ExReleaseFastMutexUnsafe",
    "ExReleaseResourceLite", "ExReleaseResourceForThreadLite",
    "ExReleaseRundownProtection", "ExReleaseRundownProtectionEx",
    "ExReleaseRundownProtectionCacheAware", "ExReleaseRundownProtectionCacheAwareEx",
    "KeReleaseMutex", "KeSetEvent",
    "ExReleasePushLockExclusive", "ExReleasePushLockShared",
    "FltReleasePushLock",
    "KeLeaveCriticalRegion", "KeLeaveGuardedRegion",
    "FsRtlExitFileSystem", "IoReleaseCancelSpinLock", "IoReleaseRemoveLock"
]

PROBE_FUNCTIONS = ["ProbeForRead", "ProbeForWrite", "MmProbeAndLockPages"]

COPY_FUNCTIONS = [
    "RtlCopyMemory", "memcpy", "memmove", "RtlMoveMemory",
    "RtlCopyBytes", "RtlCopyMemoryNonTemporal"
]

IRP_DISPATCH_NAMES = {
    0: "IRP_MJ_CREATE", 2: "IRP_MJ_CLOSE", 3: "IRP_MJ_READ", 4: "IRP_MJ_WRITE",
    14: "IRP_MJ_DEVICE_CONTROL", 15: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    18: "IRP_MJ_CLEANUP", 22: "IRP_MJ_POWER", 23: "IRP_MJ_SYSTEM_CONTROL", 27: "IRP_MJ_PNP"
}

# ============================================================
# Global State for Analysis Results
# ============================================================

_analysis_results: Dict[str, Any] = {}
_import_cache: Dict[int, str] = {}


def _build_import_cache():
    """Cache imported function names"""
    global _import_cache
    _import_cache = {}
    for i in range(ida_nalt.get_import_module_qty()):
        def imp_cb(ea, name, ordinal):
            if name:
                _import_cache[ea] = name
            return True
        ida_nalt.enum_import_names(i, imp_cb)


def _get_func_name(ea: int) -> str:
    """Get function name, checking imports first"""
    if ea in _import_cache:
        return _import_cache[ea]
    name = idc.get_name(ea)
    return name if name else f"sub_{ea:X}"


def _is_api_call(name: str, api_list: List[str]) -> bool:
    """Check if name matches any API in list"""
    return any(api in name for api in api_list)


def _get_call_arg(call_addr: int, arg_num: int) -> str:
    """Get string representation of call argument (x64)"""
    regs = ["rcx", "rdx", "r8", "r9"]
    if arg_num >= len(regs):
        return f"arg{arg_num}"

    reg = regs[arg_num]
    prev = call_addr

    for _ in range(15):
        prev = idc.prev_head(prev, 0)
        if prev == idc.BADADDR:
            break
        mnem = idc.print_insn_mnem(prev)
        if mnem in ["mov", "lea"]:
            op0 = idc.print_operand(prev, 0).lower()
            if reg in op0:
                return idc.print_operand(prev, 1)

    return f"<{reg}>"


# ============================================================
# MCP Tools
# ============================================================

@tool
@ext("race")
@idasync
def race_analyze() -> Dict[str, Any]:
    """Run full race condition analysis on the current binary.

    Analyzes the driver for:
    - Use-After-Free races
    - TOCTOU vulnerabilities
    - Reference counting bugs
    - Rundown protection issues
    - Double fetch patterns
    - Callback registration races
    - IRP completion races

    Returns comprehensive analysis results with all findings.
    """
    global _analysis_results

    _build_import_cache()

    results = {
        "globals": {},
        "dispatch_handlers": {},
        "ioctl_handlers": {},
        "shared_accesses": [],
        "race_candidates": [],
        "toctou_candidates": [],
        "refcount_issues": [],
        "rundown_issues": [],
        "function_locks": {}
    }

    # Find globals
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        seg_name = ida_segment.get_segm_name(seg)

        if seg_name in [".data", ".bss", "DATA", "BSS"]:
            seg_end = ida_segment.get_segm_end(seg_ea)
            ea = seg_ea

            while ea < seg_end and ea != idc.BADADDR:
                name = idc.get_name(ea)
                if name and not name.startswith(("unk_", "byte_", "word_", "dword_", "qword_")):
                    xref_count = len(list(idautils.XrefsTo(ea)))
                    if xref_count >= 2:
                        results["globals"][hex(ea)] = name
                ea = idc.next_head(ea, seg_end)

    # Find dispatch handlers
    for name in ["DriverEntry", "GsDriverEntry", "FxDriverEntry"]:
        driver_entry = idc.get_name_ea_simple(name)
        if driver_entry != idc.BADADDR:
            func = ida_funcs.get_func(driver_entry)
            if func:
                for head in idautils.FuncItems(driver_entry):
                    mnem = idc.print_insn_mnem(head)
                    if mnem in ["mov", "lea"]:
                        disasm = idc.GetDisasm(head)
                        for irp_idx, irp_name in IRP_DISPATCH_NAMES.items():
                            offset = 0x70 + (irp_idx * 8)
                            if f"+{offset:X}h]".lower() in disasm.lower():
                                handler = idc.get_operand_value(head, 1)
                                if handler and handler != idc.BADADDR:
                                    results["dispatch_handlers"][irp_name] = hex(handler)
            break

    # Find by naming patterns
    dispatch_patterns = [
        ("DispatchCreate", "IRP_MJ_CREATE"),
        ("DispatchClose", "IRP_MJ_CLOSE"),
        ("DispatchDeviceControl", "IRP_MJ_DEVICE_CONTROL"),
        ("DispatchCleanup", "IRP_MJ_CLEANUP"),
        ("DeviceControl", "IRP_MJ_DEVICE_CONTROL"),
    ]

    for func_ea in idautils.Functions():
        func_name = idc.get_name(func_ea)
        if func_name:
            for pattern, irp_name in dispatch_patterns:
                if pattern.lower() in func_name.lower():
                    if irp_name not in results["dispatch_handlers"]:
                        results["dispatch_handlers"][irp_name] = hex(func_ea)

    # Find IOCTL handlers
    device_control = None
    for name, addr_hex in results["dispatch_handlers"].items():
        if "DEVICE_CONTROL" in name:
            device_control = int(addr_hex, 16)
            break

    if device_control:
        func = ida_funcs.get_func(device_control)
        if func:
            for head in idautils.FuncItems(device_control):
                if idc.print_insn_mnem(head) == "cmp":
                    val = idc.get_operand_value(head, 1)
                    if val and val > 0x10000:
                        device_type = (val >> 16) & 0xFFFF
                        if device_type in [0x22, 0x80, 0x12, 0x00, 0x83]:
                            next_head = idc.next_head(head, func.end_ea)
                            if next_head != idc.BADADDR:
                                if idc.print_insn_mnem(next_head) in ["jz", "je", "jnz", "jne"]:
                                    target = idc.get_operand_value(next_head, 0)
                                    if target and target != idc.BADADDR:
                                        results["ioctl_handlers"][hex(val)] = hex(target)

    # Analyze handlers for races
    analyzed_funcs = set()
    all_handlers = []
    for addr_hex in results["dispatch_handlers"].values():
        all_handlers.append(int(addr_hex, 16))
    for addr_hex in results["ioctl_handlers"].values():
        all_handlers.append(int(addr_hex, 16))

    def analyze_function(func_ea, locks_held, depth=4):
        if depth <= 0 or func_ea in analyzed_funcs:
            return
        analyzed_funcs.add(func_ea)

        func = ida_funcs.get_func(func_ea)
        if not func:
            return

        func_name = _get_func_name(func_ea)
        current_locks = locks_held.copy()

        for head in idautils.FuncItems(func_ea):
            mnem = idc.print_insn_mnem(head)

            if mnem == "call":
                target = idc.get_operand_value(head, 0)
                if target == idc.BADADDR:
                    continue

                target_name = _get_func_name(target)

                # Track locks
                if _is_api_call(target_name, LOCK_ACQUIRE_FUNCTIONS):
                    lock_name = target_name.split("!")[-1] if "!" in target_name else target_name
                    current_locks.add(lock_name)
                    if hex(func_ea) not in results["function_locks"]:
                        results["function_locks"][hex(func_ea)] = []
                    results["function_locks"][hex(func_ea)].append(lock_name)

                elif _is_api_call(target_name, LOCK_RELEASE_FUNCTIONS):
                    lock_name = target_name.replace("Release", "Acquire")
                    current_locks.discard(lock_name)

                # Track free operations
                elif _is_api_call(target_name, FREE_FUNCTIONS):
                    results["shared_accesses"].append({
                        "address": hex(head),
                        "function": hex(func_ea),
                        "function_name": func_name,
                        "access_type": "free",
                        "target": _get_call_arg(head, 0),
                        "protected_by": list(current_locks)
                    })

                # Recurse
                if target not in _import_cache:
                    analyze_function(target, current_locks, depth - 1)

            # Check global access
            for i in range(2):
                op_value = idc.get_operand_value(head, i)
                if hex(op_value) in results["globals"]:
                    access_type = "write" if (i == 0 and mnem in ["mov", "xchg", "add", "sub"]) else "read"
                    results["shared_accesses"].append({
                        "address": hex(head),
                        "function": hex(func_ea),
                        "function_name": func_name,
                        "access_type": access_type,
                        "target": results["globals"][hex(op_value)],
                        "protected_by": list(current_locks)
                    })

    for handler in all_handlers:
        analyze_function(handler, set())

    # Detect races
    by_target = defaultdict(list)
    for access in results["shared_accesses"]:
        by_target[access["target"]].append(access)

    for target, accesses in by_target.items():
        funcs = set(a["function"] for a in accesses)
        if len(funcs) < 2:
            continue

        frees = [a for a in accesses if a["access_type"] == "free"]
        reads = [a for a in accesses if a["access_type"] == "read"]
        writes = [a for a in accesses if a["access_type"] == "write"]

        # UAF detection
        for free in frees:
            for read in reads:
                if free["function"] != read["function"]:
                    common_locks = set(free["protected_by"]) & set(read["protected_by"])
                    if not common_locks:
                        results["race_candidates"].append({
                            "severity": "critical",
                            "race_type": "use_after_free",
                            "reason": f"FREE in {free['function_name']} vs READ in {read['function_name']}",
                            "target": target,
                            "access1": free,
                            "access2": read
                        })

            for write in writes:
                if free["function"] != write["function"]:
                    common_locks = set(free["protected_by"]) & set(write["protected_by"])
                    if not common_locks:
                        results["race_candidates"].append({
                            "severity": "critical",
                            "race_type": "use_after_free",
                            "reason": f"FREE in {free['function_name']} vs WRITE in {write['function_name']}",
                            "target": target,
                            "access1": free,
                            "access2": write
                        })

        # Write-Write races
        for i, w1 in enumerate(writes):
            for w2 in writes[i+1:]:
                if w1["function"] != w2["function"]:
                    common_locks = set(w1["protected_by"]) & set(w2["protected_by"])
                    if not common_locks:
                        results["race_candidates"].append({
                            "severity": "high",
                            "race_type": "data_corruption",
                            "reason": f"Concurrent WRITE in {w1['function_name']} and {w2['function_name']}",
                            "target": target,
                            "access1": w1,
                            "access2": w2
                        })

    # Find TOCTOU
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        func_name = _get_func_name(func_ea)
        probe_addr = None
        probe_type = None

        for head in idautils.FuncItems(func_ea):
            if idc.print_insn_mnem(head) == "call":
                target = idc.get_operand_value(head, 0)
                if target == idc.BADADDR:
                    continue

                target_name = _get_func_name(target)

                if _is_api_call(target_name, PROBE_FUNCTIONS):
                    probe_addr = head
                    probe_type = target_name

                elif probe_addr and _is_api_call(target_name, COPY_FUNCTIONS):
                    gap = 0
                    addr = probe_addr
                    while addr < head:
                        addr = idc.next_head(addr, head + 1)
                        gap += 1

                    if gap > 5:
                        results["toctou_candidates"].append({
                            "function": hex(func_ea),
                            "function_name": func_name,
                            "check_address": hex(probe_addr),
                            "use_address": hex(head),
                            "gap_instructions": gap,
                            "check_type": probe_type,
                            "use_type": target_name
                        })
                    probe_addr = None

    # Find refcount bugs
    ref_inc = ["ObfReferenceObject", "ObReferenceObject", "InterlockedIncrement", "ExAcquireRundownProtection"]
    ref_dec = ["ObfDereferenceObject", "ObDereferenceObject", "InterlockedDecrement", "ExReleaseRundownProtection"]

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        func_name = _get_func_name(func_ea)
        increments = []
        decrements = []

        for head in idautils.FuncItems(func_ea):
            if idc.print_insn_mnem(head) == "call":
                target = idc.get_operand_value(head, 0)
                if target == idc.BADADDR:
                    continue

                target_name = _get_func_name(target)

                if _is_api_call(target_name, ref_inc):
                    increments.append(head)
                elif _is_api_call(target_name, ref_dec):
                    decrements.append(head)

        if decrements and len(decrements) > len(increments):
            results["refcount_issues"].append({
                "function": hex(func_ea),
                "function_name": func_name,
                "increments": len(increments),
                "decrements": len(decrements),
                "issue_type": "more_decrements_than_increments"
            })

    # Find rundown issues
    rundown_acquire = ["ExAcquireRundownProtection", "ExAcquireRundownProtectionEx"]

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        func_name = _get_func_name(func_ea)

        for head in idautils.FuncItems(func_ea):
            if idc.print_insn_mnem(head) == "call":
                target = idc.get_operand_value(head, 0)
                if target == idc.BADADDR:
                    continue

                target_name = _get_func_name(target)

                if _is_api_call(target_name, rundown_acquire):
                    next_head = idc.next_head(head, func.end_ea)
                    if next_head != idc.BADADDR:
                        next_mnem = idc.print_insn_mnem(next_head)
                        if next_mnem not in ["test", "cmp", "and"]:
                            results["rundown_issues"].append({
                                "function": hex(func_ea),
                                "function_name": func_name,
                                "address": hex(head),
                                "issue_type": "unchecked_rundown_acquire",
                                "details": "ExAcquireRundownProtection return not checked"
                            })

    # Calculate summary
    critical = len([r for r in results["race_candidates"] if r["severity"] == "critical"])
    high = len([r for r in results["race_candidates"] if r["severity"] == "high"])

    results["summary"] = {
        "total_globals": len(results["globals"]),
        "total_dispatch_handlers": len(results["dispatch_handlers"]),
        "total_ioctl_handlers": len(results["ioctl_handlers"]),
        "total_race_candidates": len(results["race_candidates"]),
        "critical_races": critical,
        "high_races": high,
        "toctou_issues": len(results["toctou_candidates"]),
        "refcount_issues": len(results["refcount_issues"]),
        "rundown_issues": len(results["rundown_issues"])
    }

    _analysis_results = results
    return results


@tool
@ext("race")
@idasync
def race_get_summary() -> Dict[str, Any]:
    """Get summary of race condition analysis.

    Returns counts of different vulnerability types found.
    Run race_analyze first if no results available.
    """
    if not _analysis_results:
        return {"error": "No analysis results. Run race_analyze first."}

    return _analysis_results.get("summary", {})


@tool
@ext("race")
@idasync
def race_get_races(severity: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get detected race condition candidates.

    Args:
        severity: Filter by severity level (critical, high, medium)

    Returns list of race candidates with details about conflicting accesses.
    """
    if not _analysis_results:
        return [{"error": "No analysis results. Run race_analyze first."}]

    races = _analysis_results.get("race_candidates", [])
    if severity:
        races = [r for r in races if r["severity"] == severity]

    return races


@tool
@ext("race")
@idasync
def race_get_toctou() -> List[Dict[str, Any]]:
    """Get TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities.

    Returns patterns where ProbeForRead/Write is followed by
    memory copy with significant gap between check and use.
    """
    if not _analysis_results:
        return [{"error": "No analysis results. Run race_analyze first."}]

    return _analysis_results.get("toctou_candidates", [])


@tool
@ext("race")
@idasync
def race_get_refcount() -> List[Dict[str, Any]]:
    """Get reference counting issues.

    Returns functions with more decrements than increments
    or potential double-decrement patterns.
    """
    if not _analysis_results:
        return [{"error": "No analysis results. Run race_analyze first."}]

    return _analysis_results.get("refcount_issues", [])


@tool
@ext("race")
@idasync
def race_get_rundown() -> List[Dict[str, Any]]:
    """Get rundown protection issues.

    Returns cases where ExAcquireRundownProtection return value
    is not checked, which can lead to use-after-rundown bugs.
    """
    if not _analysis_results:
        return [{"error": "No analysis results. Run race_analyze first."}]

    return _analysis_results.get("rundown_issues", [])


@tool
@ext("race")
@idasync
def race_get_handlers() -> Dict[str, Any]:
    """Get IRP dispatch and IOCTL handlers.

    Returns identified entry points for the driver including
    IRP_MJ_* dispatch routines and IOCTL code handlers.
    """
    if not _analysis_results:
        return {"error": "No analysis results. Run race_analyze first."}

    return {
        "dispatch_handlers": _analysis_results.get("dispatch_handlers", {}),
        "ioctl_handlers": _analysis_results.get("ioctl_handlers", {})
    }


@tool
@ext("race")
@idasync
def race_get_globals() -> Dict[str, str]:
    """Get shared global variables.

    Returns global variables that are accessed from multiple
    locations, which are potential race condition targets.
    """
    if not _analysis_results:
        return {"error": "No analysis results. Run race_analyze first."}

    return _analysis_results.get("globals", {})


@tool
@ext("race")
@idasync
def race_get_function_locks(address: str) -> Dict[str, Any]:
    """Get locks used by a specific function.

    Args:
        address: Function address in hex (e.g., "0x140001000")

    Returns list of lock acquire calls made by the function.
    """
    if not _analysis_results:
        return {"error": "No analysis results. Run race_analyze first."}

    locks = _analysis_results.get("function_locks", {})
    return {
        "address": address,
        "locks": locks.get(address, [])
    }


@tool
@ext("race")
@idasync
def race_analyze_function(address: str) -> Dict[str, Any]:
    """Analyze a specific function for race-related patterns.

    Args:
        address: Function address in hex (e.g., "0x140001000")

    Returns detailed analysis of the function including:
    - Lock operations
    - Memory allocations/frees
    - Global variable accesses
    - Potential race patterns
    """
    try:
        func_ea = int(address, 16) if address.startswith("0x") else int(address)
    except:
        return {"error": "Invalid address format"}

    func = ida_funcs.get_func(func_ea)
    if not func:
        return {"error": "No function at address"}

    _build_import_cache()

    func_name = _get_func_name(func_ea)

    result = {
        "address": hex(func_ea),
        "name": func_name,
        "lock_acquires": [],
        "lock_releases": [],
        "allocs": [],
        "frees": [],
        "global_reads": [],
        "global_writes": [],
        "calls": []
    }

    for head in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(head)

        if mnem == "call":
            target = idc.get_operand_value(head, 0)
            if target == idc.BADADDR:
                continue

            target_name = _get_func_name(target)

            call_info = {
                "address": hex(head),
                "target": target_name
            }

            if _is_api_call(target_name, LOCK_ACQUIRE_FUNCTIONS):
                result["lock_acquires"].append(call_info)
            elif _is_api_call(target_name, LOCK_RELEASE_FUNCTIONS):
                result["lock_releases"].append(call_info)
            elif _is_api_call(target_name, ALLOC_FUNCTIONS):
                call_info["size_arg"] = _get_call_arg(head, 1)
                result["allocs"].append(call_info)
            elif _is_api_call(target_name, FREE_FUNCTIONS):
                call_info["ptr_arg"] = _get_call_arg(head, 0)
                result["frees"].append(call_info)
            else:
                result["calls"].append(call_info)

    # Check for imbalances
    result["analysis"] = {
        "lock_balance": len(result["lock_acquires"]) - len(result["lock_releases"]),
        "alloc_free_balance": len(result["allocs"]) - len(result["frees"]),
        "warnings": []
    }

    if result["analysis"]["lock_balance"] != 0:
        result["analysis"]["warnings"].append(
            f"Lock imbalance: {len(result['lock_acquires'])} acquires vs {len(result['lock_releases'])} releases"
        )

    if len(result["frees"]) > len(result["allocs"]):
        result["analysis"]["warnings"].append(
            f"More frees than allocs: potential double-free or external allocation"
        )

    return result


@tool
@ext("race")
@idasync
def race_find_pattern(pattern: str) -> List[Dict[str, Any]]:
    """Search for specific race-related API patterns.

    Args:
        pattern: API pattern to search for (e.g., "Rundown", "SpinLock", "Reference")

    Returns list of functions containing matching API calls.
    """
    _build_import_cache()

    results = []
    pattern_lower = pattern.lower()

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        func_name = _get_func_name(func_ea)
        matches = []

        for head in idautils.FuncItems(func_ea):
            if idc.print_insn_mnem(head) == "call":
                target = idc.get_operand_value(head, 0)
                if target == idc.BADADDR:
                    continue

                target_name = _get_func_name(target)

                if pattern_lower in target_name.lower():
                    matches.append({
                        "address": hex(head),
                        "api": target_name
                    })

        if matches:
            results.append({
                "function": hex(func_ea),
                "function_name": func_name,
                "matches": matches
            })

    return results


@tool
@ext("race")
@idasync
def race_get_full_results() -> Dict[str, Any]:
    """Get full analysis results including all findings.

    Returns complete analysis data from the last race_analyze run.
    """
    if not _analysis_results:
        return {"error": "No analysis results. Run race_analyze first."}

    return _analysis_results
