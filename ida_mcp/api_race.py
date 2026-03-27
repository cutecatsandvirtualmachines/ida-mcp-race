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

# Driver entry point patterns for different driver types
DRIVER_ENTRY_PATTERNS = [
    # Standard WDM/KMDF
    "DriverEntry", "GsDriverEntry", "FxDriverEntry",
    # StorPort miniport
    "StorPortInitialize", "iaStorVD_Initialize", "HwInitialize",
    # NDIS miniport
    "NdisMRegisterMiniportDriver", "DriverEntry",
    # WDF
    "WdfDriverCreate",
    # Filter drivers
    "FltRegisterFilter",
]

# StorPort miniport callback names
STORPORT_CALLBACKS = [
    "HwFindAdapter", "HwInitialize", "HwStartIo", "HwInterrupt",
    "HwResetBus", "HwAdapterControl", "HwBuildIo", "HwFreeAdapterResources",
    "HwProcessServiceRequest", "HwCompleteServiceIrp", "HwInitializeTracing",
    "HwCleanupTracing", "HwTracingEnabled", "HwUnitControl", "HwStateChange"
]

# NDIS miniport callback names
NDIS_CALLBACKS = [
    "MiniportInitializeEx", "MiniportHaltEx", "MiniportPause", "MiniportRestart",
    "MiniportOidRequest", "MiniportSendNetBufferLists", "MiniportReturnNetBufferLists",
    "MiniportCancelSend", "MiniportDevicePnPEventNotify", "MiniportShutdownEx",
    "MiniportCheckForHangEx", "MiniportResetEx", "MiniportCancelOidRequest",
    "MiniportDirectOidRequest", "MiniportCancelDirectOidRequest"
]

# Patterns to identify driver type from strings/imports
DRIVER_TYPE_INDICATORS = {
    "storport": ["StorPort", "STOR_", "HW_INITIALIZATION_DATA", "iaStorVD", "NvmePort"],
    "ndis": ["NDIS", "Ndis", "MINIPORT_", "NET_BUFFER"],
    "wdf": ["Wdf", "WDF_", "WDFDRIVER", "WDFDEVICE"],
    "filter": ["Flt", "FLT_", "PFLT_", "FilterDriver"],
    "wdm": ["IoCreateDevice", "IRP_MJ_", "DriverObject->MajorFunction"]
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


def _detect_driver_type() -> Dict[str, Any]:
    """Detect the type of driver from imports and strings"""
    driver_info = {
        "type": "unknown",
        "indicators": [],
        "entry_points": []
    }

    # Check imports
    for ea, name in _import_cache.items():
        for dtype, patterns in DRIVER_TYPE_INDICATORS.items():
            for pattern in patterns:
                if pattern.lower() in name.lower():
                    if dtype not in driver_info["indicators"]:
                        driver_info["indicators"].append(dtype)

    # Check strings
    for s in idautils.Strings():
        str_val = str(s)
        for dtype, patterns in DRIVER_TYPE_INDICATORS.items():
            for pattern in patterns:
                if pattern in str_val:
                    if dtype not in driver_info["indicators"]:
                        driver_info["indicators"].append(dtype)

    # Determine primary type
    if "storport" in driver_info["indicators"]:
        driver_info["type"] = "storport"
    elif "ndis" in driver_info["indicators"]:
        driver_info["type"] = "ndis"
    elif "filter" in driver_info["indicators"]:
        driver_info["type"] = "filter"
    elif "wdf" in driver_info["indicators"]:
        driver_info["type"] = "wdf"
    else:
        driver_info["type"] = "wdm"

    return driver_info


def _find_storport_handlers() -> Dict[str, int]:
    """Find StorPort miniport callback handlers"""
    handlers = {}

    # Look for HW_INITIALIZATION_DATA setup
    # These are typically set up in DriverEntry before StorPortInitialize

    # Search for known callback function name patterns
    for func_ea in idautils.Functions():
        func_name = idc.get_name(func_ea)
        if not func_name:
            continue

        # Check against StorPort callback names
        for cb_name in STORPORT_CALLBACKS:
            if cb_name.lower() in func_name.lower():
                handlers[cb_name] = func_ea

        # Also check for common patterns
        if "StartIo" in func_name or "HwStartIo" in func_name:
            handlers["HwStartIo"] = func_ea
        elif "BuildIo" in func_name or "HwBuildIo" in func_name:
            handlers["HwBuildIo"] = func_ea
        elif "ProcessServiceRequest" in func_name:
            handlers["HwProcessServiceRequest"] = func_ea

    # Search for StorPortInitialize calls and trace back to find callback assignments
    for ea, name in _import_cache.items():
        if "StorPortInitialize" in name:
            # Find xrefs to StorPortInitialize
            for xref in idautils.XrefsTo(ea):
                func = ida_funcs.get_func(xref.frm)
                if func:
                    # The 3rd argument (r8) contains HW_INITIALIZATION_DATA pointer
                    # Analyze the function to find callback assignments
                    _analyze_hw_init_data(func.start_ea, handlers)

    return handlers


def _analyze_hw_init_data(func_ea: int, handlers: Dict[str, int]):
    """Analyze function to find HW_INITIALIZATION_DATA callback assignments"""
    func = ida_funcs.get_func(func_ea)
    if not func:
        return

    # StorPort HW_INITIALIZATION_DATA callback offsets (x64)
    # These vary by structure version but common offsets:
    callback_offsets = {
        0x08: "HwFindAdapter",
        0x10: "HwInitialize",
        0x18: "HwStartIo",
        0x20: "HwInterrupt",
        0x28: "HwResetBus",
        0x30: "HwAdapterControl",
        0x38: "HwBuildIo",
        0x78: "HwProcessServiceRequest",
        0x80: "HwCompleteServiceIrp",
    }

    for head in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(head)
        if mnem in ["mov", "lea"]:
            disasm = idc.GetDisasm(head)
            # Look for patterns like mov [rbp+offset], func_addr
            for offset, cb_name in callback_offsets.items():
                if f"+{offset:X}h]" in disasm.upper() or f"+0x{offset:X}]" in disasm.upper():
                    target = idc.get_operand_value(head, 1)
                    if target and target != idc.BADADDR:
                        func_at = ida_funcs.get_func(target)
                        if func_at:
                            handlers[cb_name] = target


def _find_ndis_handlers() -> Dict[str, int]:
    """Find NDIS miniport callback handlers"""
    handlers = {}

    # Search for NDIS callback patterns in function names
    for func_ea in idautils.Functions():
        func_name = idc.get_name(func_ea)
        if not func_name:
            continue

        for cb_name in NDIS_CALLBACKS:
            if cb_name.lower() in func_name.lower():
                handlers[cb_name] = func_ea

    return handlers


def _find_wdf_handlers() -> Dict[str, int]:
    """Find WDF callback handlers"""
    handlers = {}

    wdf_callbacks = [
        "EvtDriverDeviceAdd", "EvtDevicePrepareHardware", "EvtDeviceReleaseHardware",
        "EvtDeviceD0Entry", "EvtDeviceD0Exit", "EvtIoRead", "EvtIoWrite",
        "EvtIoDeviceControl", "EvtIoInternalDeviceControl", "EvtIoDefault",
        "EvtRequestCancel", "EvtFileCreate", "EvtFileClose", "EvtFileCleanup"
    ]

    for func_ea in idautils.Functions():
        func_name = idc.get_name(func_ea)
        if not func_name:
            continue

        for cb_name in wdf_callbacks:
            if cb_name.lower() in func_name.lower():
                handlers[cb_name] = func_ea

    return handlers


def _find_all_handlers() -> Dict[str, Any]:
    """Find all entry points/handlers based on driver type"""
    driver_info = _detect_driver_type()
    handlers = {
        "driver_type": driver_info["type"],
        "dispatch_handlers": {},
        "callbacks": {},
        "ioctl_handlers": {}
    }

    # Always try to find standard dispatch handlers
    for name in ["DriverEntry", "GsDriverEntry", "FxDriverEntry"]:
        ea = idc.get_name_ea_simple(name)
        if ea != idc.BADADDR:
            handlers["dispatch_handlers"]["DriverEntry"] = ea
            break

    # Type-specific handler discovery
    if driver_info["type"] == "storport":
        handlers["callbacks"] = _find_storport_handlers()
    elif driver_info["type"] == "ndis":
        handlers["callbacks"] = _find_ndis_handlers()
    elif driver_info["type"] == "wdf":
        handlers["callbacks"] = _find_wdf_handlers()

    # Find standard WDM dispatch handlers
    driver_entry = handlers["dispatch_handlers"].get("DriverEntry")
    if driver_entry:
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
                                handlers["dispatch_handlers"][irp_name] = handler

    # Also search by function name patterns
    dispatch_patterns = [
        ("DispatchCreate", "IRP_MJ_CREATE"),
        ("DispatchClose", "IRP_MJ_CLOSE"),
        ("DispatchDeviceControl", "IRP_MJ_DEVICE_CONTROL"),
        ("DispatchCleanup", "IRP_MJ_CLEANUP"),
        ("DeviceControl", "IRP_MJ_DEVICE_CONTROL"),
        ("DeviceIoControl", "IRP_MJ_DEVICE_CONTROL"),
        ("InternalDeviceControl", "IRP_MJ_INTERNAL_DEVICE_CONTROL"),
    ]

    for func_ea in idautils.Functions():
        func_name = idc.get_name(func_ea)
        if func_name:
            for pattern, irp_name in dispatch_patterns:
                if pattern.lower() in func_name.lower():
                    if irp_name not in handlers["dispatch_handlers"]:
                        handlers["dispatch_handlers"][irp_name] = func_ea

    return handlers


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

    # Use improved handler detection
    handler_info = _find_all_handlers()

    results = {
        "driver_type": handler_info["driver_type"],
        "globals": {},
        "dispatch_handlers": {k: hex(v) if isinstance(v, int) else v for k, v in handler_info["dispatch_handlers"].items()},
        "callbacks": {k: hex(v) if isinstance(v, int) else v for k, v in handler_info["callbacks"].items()},
        "ioctl_handlers": {k: hex(v) if isinstance(v, int) else v for k, v in handler_info["ioctl_handlers"].items()},
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

        if seg_name in [".data", ".bss", "DATA", "BSS", ".rdata"]:
            seg_end = ida_segment.get_segm_end(seg_ea)
            ea = seg_ea

            while ea < seg_end and ea != idc.BADADDR:
                name = idc.get_name(ea)
                if name and not name.startswith(("unk_", "byte_", "word_", "dword_", "qword_", "off_", "loc_")):
                    xref_count = len(list(idautils.XrefsTo(ea)))
                    if xref_count >= 2:
                        results["globals"][hex(ea)] = name
                ea = idc.next_head(ea, seg_end)

    # Find IOCTL handlers from DeviceControl
    device_control = None
    for name, addr_hex in results["dispatch_handlers"].items():
        if "DEVICE_CONTROL" in name:
            device_control = int(addr_hex, 16) if isinstance(addr_hex, str) else addr_hex
            break

    if device_control:
        func = ida_funcs.get_func(device_control)
        if func:
            for head in idautils.FuncItems(device_control):
                if idc.print_insn_mnem(head) == "cmp":
                    val = idc.get_operand_value(head, 1)
                    if val and val > 0x10000:
                        device_type = (val >> 16) & 0xFFFF
                        if device_type in [0x22, 0x80, 0x12, 0x00, 0x83, 0x84, 0xF0]:
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
        try:
            all_handlers.append(int(addr_hex, 16) if isinstance(addr_hex, str) else addr_hex)
        except:
            pass
    for addr_hex in results["ioctl_handlers"].values():
        try:
            all_handlers.append(int(addr_hex, 16) if isinstance(addr_hex, str) else addr_hex)
        except:
            pass
    # Include driver-specific callbacks (StorPort, NDIS, WDF)
    for addr_hex in results["callbacks"].values():
        try:
            all_handlers.append(int(addr_hex, 16) if isinstance(addr_hex, str) else addr_hex)
        except:
            pass

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
        "driver_type": results.get("driver_type", "unknown"),
        "total_globals": len(results["globals"]),
        "total_dispatch_handlers": len(results["dispatch_handlers"]),
        "total_callbacks": len(results.get("callbacks", {})),
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
def race_detect_driver_type() -> Dict[str, Any]:
    """Detect the type of driver being analyzed.

    Identifies driver type from imports, strings, and patterns:
    - storport: StorPort miniport drivers (storage)
    - ndis: NDIS miniport drivers (network)
    - wdf: Windows Driver Framework (KMDF/UMDF)
    - filter: Filesystem filter drivers
    - wdm: Standard WDM drivers

    Returns driver type and indicators found.
    """
    _build_import_cache()
    return _detect_driver_type()


@tool
@ext("race")
@idasync
def race_get_all_handlers() -> Dict[str, Any]:
    """Get all detected handlers/callbacks for the driver.

    Returns handlers based on driver type including:
    - WDM dispatch handlers (IRP_MJ_*)
    - StorPort callbacks (HwStartIo, HwBuildIo, etc.)
    - NDIS callbacks (MiniportOidRequest, etc.)
    - WDF callbacks (EvtIoDeviceControl, etc.)
    """
    _build_import_cache()
    handlers = _find_all_handlers()

    # Convert addresses to hex strings
    result = {
        "driver_type": handlers["driver_type"],
        "dispatch_handlers": {k: hex(v) if isinstance(v, int) else v for k, v in handlers["dispatch_handlers"].items()},
        "callbacks": {k: hex(v) if isinstance(v, int) else v for k, v in handlers["callbacks"].items()},
        "ioctl_handlers": {k: hex(v) if isinstance(v, int) else v for k, v in handlers["ioctl_handlers"].items()},
    }

    return result


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
