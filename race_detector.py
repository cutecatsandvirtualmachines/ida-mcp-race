# ============================================================
# IDA Pro Race Condition Detector Plugin
# Version: 2.0
# For IDA Pro 9.0+
# ============================================================
#
# This plugin provides:
# 1. Automated race condition detection in Windows drivers
# 2. HTTP API server for MCP/Claude integration
# 3. Interactive analysis UI
#
# Installation: Copy to IDA plugins folder
# Usage: Edit -> Plugins -> Race Detector (or Ctrl+Shift+R)
# ============================================================

import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import ida_xref
import ida_kernwin
import ida_nalt

import json
import threading
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from typing import Set, Dict, List, Optional, Tuple
from enum import Enum

# Try to import Hex-Rays
try:
    import ida_hexrays
    HAS_HEXRAYS = True
except:
    HAS_HEXRAYS = False

# ============================================================
# Configuration
# ============================================================

PLUGIN_NAME = "Race Detector"
PLUGIN_HOTKEY = "Ctrl+Shift+R"
HTTP_PORT = 9100

# Windows kernel functions for detection
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

PROBE_FUNCTIONS = [
    "ProbeForRead", "ProbeForWrite", "MmProbeAndLockPages"
]

COPY_FUNCTIONS = [
    "RtlCopyMemory", "memcpy", "memmove", "RtlMoveMemory",
    "RtlCopyBytes", "RtlCopyMemoryNonTemporal"
]

CALLBACK_REGISTER_FUNCTIONS = [
    "PsSetCreateProcessNotifyRoutine", "PsSetCreateProcessNotifyRoutineEx",
    "PsSetCreateThreadNotifyRoutine", "PsSetLoadImageNotifyRoutine",
    "CmRegisterCallback", "CmRegisterCallbackEx",
    "ObRegisterCallbacks", "FltRegisterFilter",
    "IoRegisterPlugPlayNotification", "IoRegisterShutdownNotification"
]

IRP_DISPATCH_NAMES = {
    0: "IRP_MJ_CREATE",
    1: "IRP_MJ_CREATE_NAMED_PIPE",
    2: "IRP_MJ_CLOSE",
    3: "IRP_MJ_READ",
    4: "IRP_MJ_WRITE",
    5: "IRP_MJ_QUERY_INFORMATION",
    6: "IRP_MJ_SET_INFORMATION",
    7: "IRP_MJ_QUERY_EA",
    8: "IRP_MJ_SET_EA",
    9: "IRP_MJ_FLUSH_BUFFERS",
    10: "IRP_MJ_QUERY_VOLUME_INFORMATION",
    11: "IRP_MJ_SET_VOLUME_INFORMATION",
    12: "IRP_MJ_DIRECTORY_CONTROL",
    13: "IRP_MJ_FILE_SYSTEM_CONTROL",
    14: "IRP_MJ_DEVICE_CONTROL",
    15: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    16: "IRP_MJ_SHUTDOWN",
    17: "IRP_MJ_LOCK_CONTROL",
    18: "IRP_MJ_CLEANUP",
    19: "IRP_MJ_CREATE_MAILSLOT",
    20: "IRP_MJ_QUERY_SECURITY",
    21: "IRP_MJ_SET_SECURITY",
    22: "IRP_MJ_POWER",
    23: "IRP_MJ_SYSTEM_CONTROL",
    24: "IRP_MJ_DEVICE_CHANGE",
    25: "IRP_MJ_QUERY_QUOTA",
    26: "IRP_MJ_SET_QUOTA",
    27: "IRP_MJ_PNP"
}


# ============================================================
# Data Classes
# ============================================================

class AccessType(Enum):
    READ = "read"
    WRITE = "write"
    FREE = "free"
    ALLOC = "alloc"
    LOCK_ACQUIRE = "lock_acquire"
    LOCK_RELEASE = "lock_release"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SharedAccess:
    address: int
    function: int
    function_name: str
    access_type: str
    target: str
    target_address: int
    protected_by: List[str]
    call_depth: int = 0

    def to_dict(self):
        return {
            "address": hex(self.address),
            "function": hex(self.function),
            "function_name": self.function_name,
            "access_type": self.access_type,
            "target": self.target,
            "target_address": hex(self.target_address) if self.target_address else None,
            "protected_by": self.protected_by,
            "call_depth": self.call_depth
        }


@dataclass
class RaceCandidate:
    access1: SharedAccess
    access2: SharedAccess
    reason: str
    severity: str
    race_type: str
    mitigation: str = ""

    def to_dict(self):
        return {
            "access1": self.access1.to_dict(),
            "access2": self.access2.to_dict(),
            "reason": self.reason,
            "severity": self.severity,
            "race_type": self.race_type,
            "mitigation": self.mitigation
        }


@dataclass
class TOCTOUCandidate:
    function: int
    function_name: str
    check_address: int
    use_address: int
    gap_instructions: int
    check_type: str
    use_type: str

    def to_dict(self):
        return {
            "function": hex(self.function),
            "function_name": self.function_name,
            "check_address": hex(self.check_address),
            "use_address": hex(self.use_address),
            "gap_instructions": self.gap_instructions,
            "check_type": self.check_type,
            "use_type": self.use_type
        }


@dataclass
class RefcountIssue:
    function: int
    function_name: str
    increments: int
    decrements: int
    increment_addrs: List[int]
    decrement_addrs: List[int]
    issue_type: str

    def to_dict(self):
        return {
            "function": hex(self.function),
            "function_name": self.function_name,
            "increments": self.increments,
            "decrements": self.decrements,
            "increment_addrs": [hex(a) for a in self.increment_addrs],
            "decrement_addrs": [hex(a) for a in self.decrement_addrs],
            "issue_type": self.issue_type
        }


@dataclass
class RundownIssue:
    function: int
    function_name: str
    address: int
    issue_type: str
    details: str

    def to_dict(self):
        return {
            "function": hex(self.function),
            "function_name": self.function_name,
            "address": hex(self.address),
            "issue_type": self.issue_type,
            "details": self.details
        }


@dataclass
class AnalysisResults:
    globals: Dict[int, str] = field(default_factory=dict)
    dispatch_handlers: Dict[str, int] = field(default_factory=dict)
    ioctl_handlers: Dict[int, int] = field(default_factory=dict)
    shared_accesses: List[SharedAccess] = field(default_factory=list)
    race_candidates: List[RaceCandidate] = field(default_factory=list)
    toctou_candidates: List[TOCTOUCandidate] = field(default_factory=list)
    refcount_issues: List[RefcountIssue] = field(default_factory=list)
    rundown_issues: List[RundownIssue] = field(default_factory=list)
    function_locks: Dict[int, List[str]] = field(default_factory=dict)
    call_graph: Dict[int, List[int]] = field(default_factory=dict)

    def to_dict(self):
        return {
            "globals": {hex(k): v for k, v in self.globals.items()},
            "dispatch_handlers": {k: hex(v) for k, v in self.dispatch_handlers.items()},
            "ioctl_handlers": {hex(k): hex(v) for k, v in self.ioctl_handlers.items()},
            "shared_accesses": [a.to_dict() for a in self.shared_accesses],
            "race_candidates": [r.to_dict() for r in self.race_candidates],
            "toctou_candidates": [t.to_dict() for t in self.toctou_candidates],
            "refcount_issues": [r.to_dict() for r in self.refcount_issues],
            "rundown_issues": [r.to_dict() for r in self.rundown_issues],
            "function_locks": {hex(k): v for k, v in self.function_locks.items()},
            "summary": self.get_summary()
        }

    def get_summary(self):
        critical = len([r for r in self.race_candidates if r.severity == "critical"])
        high = len([r for r in self.race_candidates if r.severity == "high"])
        medium = len([r for r in self.race_candidates if r.severity == "medium"])

        return {
            "total_globals": len(self.globals),
            "total_dispatch_handlers": len(self.dispatch_handlers),
            "total_ioctl_handlers": len(self.ioctl_handlers),
            "total_shared_accesses": len(self.shared_accesses),
            "total_race_candidates": len(self.race_candidates),
            "critical_races": critical,
            "high_races": high,
            "medium_races": medium,
            "toctou_issues": len(self.toctou_candidates),
            "refcount_issues": len(self.refcount_issues),
            "rundown_issues": len(self.rundown_issues)
        }


# ============================================================
# Main Analysis Engine
# ============================================================

class RaceDetectorEngine:
    def __init__(self):
        self.results = AnalysisResults()
        self.analyzed_funcs = set()
        self.import_cache = {}
        self._build_import_cache()

    def _build_import_cache(self):
        """Cache imported function names for fast lookup"""
        for i in range(ida_nalt.get_import_module_qty()):
            def imp_cb(ea, name, ordinal):
                if name:
                    self.import_cache[ea] = name
                return True
            ida_nalt.enum_import_names(i, imp_cb)

    def get_func_name(self, ea):
        """Get function name, checking imports first"""
        if ea in self.import_cache:
            return self.import_cache[ea]
        name = idc.get_name(ea)
        if name:
            return name
        return f"sub_{ea:X}"

    def is_api_call(self, name, api_list):
        """Check if name matches any API in list"""
        for api in api_list:
            if api in name:
                return True
        return False

    def run_full_analysis(self):
        """Run complete analysis"""
        print(f"[{PLUGIN_NAME}] Starting full analysis...")

        self.results = AnalysisResults()
        self.analyzed_funcs = set()

        self.find_globals()
        self.find_dispatch_handlers()
        self.find_ioctl_handlers()
        self.build_call_graph()
        self.analyze_all_handlers()
        self.detect_races()
        self.find_toctou_patterns()
        self.find_refcount_bugs()
        self.find_rundown_issues()
        self.find_double_fetch()
        self.find_callback_races()
        self.find_irp_races()
        self.find_pool_overflow()

        print(f"[{PLUGIN_NAME}] Analysis complete!")
        return self.results

    def find_globals(self):
        """Find global variables in data sections"""
        print(f"[{PLUGIN_NAME}] Finding globals...")

        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            seg_name = ida_segment.get_segm_name(seg)

            # Check data sections
            if seg_name in [".data", ".bss", "DATA", "BSS", ".rdata", "CONST"]:
                seg_end = ida_segment.get_segm_end(seg_ea)
                ea = seg_ea

                while ea < seg_end and ea != idc.BADADDR:
                    name = idc.get_name(ea)
                    if name and not name.startswith(("unk_", "byte_", "word_", "dword_", "qword_")):
                        # Count xrefs to determine if shared
                        xref_count = len(list(idautils.XrefsTo(ea)))
                        if xref_count >= 2:  # Multiple references = likely shared
                            self.results.globals[ea] = name

                    ea = idc.next_head(ea, seg_end)

        print(f"[{PLUGIN_NAME}] Found {len(self.results.globals)} globals")

    def find_dispatch_handlers(self):
        """Find IRP dispatch handlers"""
        print(f"[{PLUGIN_NAME}] Finding dispatch handlers...")

        # Find DriverEntry
        driver_entry = None
        for name in ["DriverEntry", "GsDriverEntry", "FxDriverEntry"]:
            ea = idc.get_name_ea_simple(name)
            if ea != idc.BADADDR:
                driver_entry = ea
                break

        if not driver_entry:
            print(f"[{PLUGIN_NAME}] DriverEntry not found by name, searching...")
            return

        # Analyze DriverEntry for dispatch table setup
        func = ida_funcs.get_func(driver_entry)
        if not func:
            return

        # Look for writes to MajorFunction array
        for head in idautils.FuncItems(driver_entry):
            mnem = idc.print_insn_mnem(head)

            if mnem in ["mov", "lea"]:
                disasm = idc.GetDisasm(head)

                for irp_idx, irp_name in IRP_DISPATCH_NAMES.items():
                    offset = 0x70 + (irp_idx * 8)
                    offset_str = f"+{offset:X}h]"
                    offset_str_lower = f"+0x{offset:x}]"

                    if offset_str.lower() in disasm.lower() or offset_str_lower in disasm.lower():
                        handler = idc.get_operand_value(head, 1)
                        if handler and handler != idc.BADADDR:
                            self.results.dispatch_handlers[irp_name] = handler

        # Also find by common naming patterns
        dispatch_patterns = [
            ("DispatchCreate", "IRP_MJ_CREATE"),
            ("DispatchClose", "IRP_MJ_CLOSE"),
            ("DispatchRead", "IRP_MJ_READ"),
            ("DispatchWrite", "IRP_MJ_WRITE"),
            ("DispatchDeviceControl", "IRP_MJ_DEVICE_CONTROL"),
            ("DispatchInternalDeviceControl", "IRP_MJ_INTERNAL_DEVICE_CONTROL"),
            ("DispatchCleanup", "IRP_MJ_CLEANUP"),
            ("DispatchPnp", "IRP_MJ_PNP"),
            ("DispatchPower", "IRP_MJ_POWER"),
            ("DeviceControl", "IRP_MJ_DEVICE_CONTROL"),
            ("DeviceIoControl", "IRP_MJ_DEVICE_CONTROL"),
        ]

        for func_ea in idautils.Functions():
            func_name = idc.get_name(func_ea)
            if func_name:
                for pattern, irp_name in dispatch_patterns:
                    if pattern.lower() in func_name.lower():
                        if irp_name not in self.results.dispatch_handlers:
                            self.results.dispatch_handlers[irp_name] = func_ea

        print(f"[{PLUGIN_NAME}] Found {len(self.results.dispatch_handlers)} dispatch handlers")

    def find_ioctl_handlers(self):
        """Find IOCTL code handlers"""
        print(f"[{PLUGIN_NAME}] Finding IOCTL handlers...")

        device_control = None
        for name, addr in self.results.dispatch_handlers.items():
            if "DEVICE_CONTROL" in name:
                device_control = addr
                break

        if not device_control:
            return

        func = ida_funcs.get_func(device_control)
        if not func:
            return

        for head in idautils.FuncItems(device_control):
            mnem = idc.print_insn_mnem(head)

            if mnem == "cmp":
                val = idc.get_operand_value(head, 1)
                if val and val > 0x10000:
                    device_type = (val >> 16) & 0xFFFF
                    if device_type in [0x22, 0x80, 0x12, 0x00, 0x83, 0x84]:
                        next_head = idc.next_head(head, func.end_ea)
                        if next_head != idc.BADADDR:
                            next_mnem = idc.print_insn_mnem(next_head)
                            if next_mnem in ["jz", "je", "jnz", "jne"]:
                                target = idc.get_operand_value(next_head, 0)
                                if target and target != idc.BADADDR:
                                    self.results.ioctl_handlers[val] = target

        print(f"[{PLUGIN_NAME}] Found {len(self.results.ioctl_handlers)} IOCTL handlers")

    def build_call_graph(self):
        """Build call graph for inter-procedural analysis"""
        print(f"[{PLUGIN_NAME}] Building call graph...")

        for func_ea in idautils.Functions():
            callees = []

            for head in idautils.FuncItems(func_ea):
                mnem = idc.print_insn_mnem(head)
                if mnem == "call":
                    target = idc.get_operand_value(head, 0)
                    if target and target != idc.BADADDR:
                        callees.append(target)

            if callees:
                self.results.call_graph[func_ea] = callees

    def analyze_all_handlers(self):
        """Analyze all dispatch and IOCTL handlers"""
        print(f"[{PLUGIN_NAME}] Analyzing handlers...")

        all_handlers = (
            list(self.results.dispatch_handlers.values()) +
            list(self.results.ioctl_handlers.values())
        )

        for handler in all_handlers:
            self.analyze_function_recursive(handler, set(), depth=5)

    def analyze_function_recursive(self, func_ea, locks_held, depth=5):
        """Recursively analyze function for shared state access"""
        if depth <= 0 or func_ea in self.analyzed_funcs:
            return

        self.analyzed_funcs.add(func_ea)

        func = ida_funcs.get_func(func_ea)
        if not func:
            return

        func_name = self.get_func_name(func_ea)
        current_locks = locks_held.copy()

        for head in idautils.FuncItems(func_ea):
            mnem = idc.print_insn_mnem(head)

            if mnem == "call":
                target = idc.get_operand_value(head, 0)
                if target == idc.BADADDR:
                    continue

                target_name = self.get_func_name(target)

                # Track lock operations
                if self.is_api_call(target_name, LOCK_ACQUIRE_FUNCTIONS):
                    lock_name = target_name.split("!")[-1] if "!" in target_name else target_name
                    current_locks.add(lock_name)
                    if func_ea not in self.results.function_locks:
                        self.results.function_locks[func_ea] = []
                    self.results.function_locks[func_ea].append(lock_name)

                elif self.is_api_call(target_name, LOCK_RELEASE_FUNCTIONS):
                    lock_name = target_name.split("!")[-1] if "!" in target_name else target_name
                    lock_name = lock_name.replace("Release", "Acquire")
                    current_locks.discard(lock_name)

                # Track free operations
                elif self.is_api_call(target_name, FREE_FUNCTIONS):
                    access = SharedAccess(
                        address=head,
                        function=func_ea,
                        function_name=func_name,
                        access_type="free",
                        target=self._get_call_arg(head, 0),
                        target_address=self._get_call_arg_value(head, 0),
                        protected_by=list(current_locks),
                        call_depth=5 - depth
                    )
                    self.results.shared_accesses.append(access)

                # Track alloc operations
                elif self.is_api_call(target_name, ALLOC_FUNCTIONS):
                    access = SharedAccess(
                        address=head,
                        function=func_ea,
                        function_name=func_name,
                        access_type="alloc",
                        target=target_name,
                        target_address=target,
                        protected_by=list(current_locks),
                        call_depth=5 - depth
                    )
                    self.results.shared_accesses.append(access)

                # Recurse into called functions
                if target not in self.import_cache:
                    self.analyze_function_recursive(target, current_locks, depth - 1)

            # Check for global variable access
            for i in range(2):
                op_type = idc.get_operand_type(head, i)
                op_value = idc.get_operand_value(head, i)

                if op_value in self.results.globals:
                    access_type = "write" if (i == 0 and mnem in ["mov", "xchg", "add", "sub", "or", "and", "xor", "inc", "dec"]) else "read"

                    access = SharedAccess(
                        address=head,
                        function=func_ea,
                        function_name=func_name,
                        access_type=access_type,
                        target=self.results.globals[op_value],
                        target_address=op_value,
                        protected_by=list(current_locks),
                        call_depth=5 - depth
                    )
                    self.results.shared_accesses.append(access)

    def _get_call_arg(self, call_addr, arg_num):
        """Get string representation of call argument"""
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

    def _get_call_arg_value(self, call_addr, arg_num):
        """Get numeric value of call argument if available"""
        regs = ["rcx", "rdx", "r8", "r9"]
        if arg_num >= len(regs):
            return 0

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
                    return idc.get_operand_value(prev, 1)

        return 0

    def detect_races(self):
        """Detect potential race conditions"""
        print(f"[{PLUGIN_NAME}] Detecting races...")

        by_target = defaultdict(list)
        for access in self.results.shared_accesses:
            by_target[access.target].append(access)

        for target, accesses in by_target.items():
            funcs = set(a.function for a in accesses)
            if len(funcs) < 2:
                continue

            frees = [a for a in accesses if a.access_type == "free"]
            reads = [a for a in accesses if a.access_type == "read"]
            writes = [a for a in accesses if a.access_type == "write"]

            # UAF: Free vs Read
            for free in frees:
                for read in reads:
                    if free.function != read.function:
                        if not self._same_lock(free, read):
                            self.results.race_candidates.append(RaceCandidate(
                                access1=free,
                                access2=read,
                                reason=f"FREE in {free.function_name} vs READ in {read.function_name} without common lock",
                                severity="critical",
                                race_type="use_after_free",
                                mitigation="Add synchronization or reference counting"
                            ))

            # UAF: Free vs Write
            for free in frees:
                for write in writes:
                    if free.function != write.function:
                        if not self._same_lock(free, write):
                            self.results.race_candidates.append(RaceCandidate(
                                access1=free,
                                access2=write,
                                reason=f"FREE in {free.function_name} vs WRITE in {write.function_name} without common lock",
                                severity="critical",
                                race_type="use_after_free",
                                mitigation="Add synchronization or reference counting"
                            ))

            # Data corruption: Write vs Write
            for i, w1 in enumerate(writes):
                for w2 in writes[i+1:]:
                    if w1.function != w2.function:
                        if not self._same_lock(w1, w2):
                            self.results.race_candidates.append(RaceCandidate(
                                access1=w1,
                                access2=w2,
                                reason=f"Concurrent WRITE in {w1.function_name} and {w2.function_name} without common lock",
                                severity="high",
                                race_type="data_corruption",
                                mitigation="Add lock around shared state modification"
                            ))

    def _same_lock(self, a1, a2):
        """Check if two accesses share a common lock"""
        return bool(set(a1.protected_by) & set(a2.protected_by))

    def find_toctou_patterns(self):
        """Find Time-of-Check Time-of-Use patterns"""
        print(f"[{PLUGIN_NAME}] Finding TOCTOU patterns...")

        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue

            func_name = self.get_func_name(func_ea)
            probe_addr = None
            probe_type = None

            for head in idautils.FuncItems(func_ea):
                mnem = idc.print_insn_mnem(head)

                if mnem == "call":
                    target = idc.get_operand_value(head, 0)
                    if target == idc.BADADDR:
                        continue

                    target_name = self.get_func_name(target)

                    if self.is_api_call(target_name, PROBE_FUNCTIONS):
                        probe_addr = head
                        probe_type = target_name

                    elif probe_addr and self.is_api_call(target_name, COPY_FUNCTIONS):
                        gap = 0
                        addr = probe_addr
                        while addr < head:
                            addr = idc.next_head(addr, head + 1)
                            gap += 1

                        if gap > 5:
                            self.results.toctou_candidates.append(TOCTOUCandidate(
                                function=func_ea,
                                function_name=func_name,
                                check_address=probe_addr,
                                use_address=head,
                                gap_instructions=gap,
                                check_type=probe_type,
                                use_type=target_name
                            ))

                        probe_addr = None

    def find_refcount_bugs(self):
        """Find reference counting bugs"""
        print(f"[{PLUGIN_NAME}] Finding refcount bugs...")

        ref_inc_funcs = ["ObfReferenceObject", "ObReferenceObject", "InterlockedIncrement",
                        "ExAcquireRundownProtection", "WdfObjectReference"]
        ref_dec_funcs = ["ObfDereferenceObject", "ObDereferenceObject", "InterlockedDecrement",
                        "ExReleaseRundownProtection", "WdfObjectDereference"]

        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue

            func_name = self.get_func_name(func_ea)
            increments = []
            decrements = []

            for head in idautils.FuncItems(func_ea):
                mnem = idc.print_insn_mnem(head)

                if mnem == "call":
                    target = idc.get_operand_value(head, 0)
                    if target == idc.BADADDR:
                        continue

                    target_name = self.get_func_name(target)

                    if self.is_api_call(target_name, ref_inc_funcs):
                        increments.append(head)
                    elif self.is_api_call(target_name, ref_dec_funcs):
                        decrements.append(head)

            if decrements and len(decrements) > len(increments):
                self.results.refcount_issues.append(RefcountIssue(
                    function=func_ea,
                    function_name=func_name,
                    increments=len(increments),
                    decrements=len(decrements),
                    increment_addrs=increments,
                    decrement_addrs=decrements,
                    issue_type="more_decrements_than_increments"
                ))

            if len(decrements) >= 2:
                for i in range(len(decrements) - 1):
                    has_inc = any(decrements[i] < inc < decrements[i+1] for inc in increments)
                    if not has_inc:
                        dist = decrements[i+1] - decrements[i]
                        if dist < 50:
                            self.results.refcount_issues.append(RefcountIssue(
                                function=func_ea,
                                function_name=func_name,
                                increments=len(increments),
                                decrements=len(decrements),
                                increment_addrs=increments,
                                decrement_addrs=[decrements[i], decrements[i+1]],
                                issue_type="potential_double_decrement"
                            ))

    def find_rundown_issues(self):
        """Find rundown protection issues"""
        print(f"[{PLUGIN_NAME}] Finding rundown issues...")

        rundown_acquire = ["ExAcquireRundownProtection", "ExAcquireRundownProtectionEx",
                          "ExAcquireRundownProtectionCacheAware"]

        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue

            func_name = self.get_func_name(func_ea)

            for head in idautils.FuncItems(func_ea):
                mnem = idc.print_insn_mnem(head)

                if mnem == "call":
                    target = idc.get_operand_value(head, 0)
                    if target == idc.BADADDR:
                        continue

                    target_name = self.get_func_name(target)

                    if self.is_api_call(target_name, rundown_acquire):
                        next_head = idc.next_head(head, func.end_ea)
                        if next_head != idc.BADADDR:
                            next_mnem = idc.print_insn_mnem(next_head)

                            if next_mnem not in ["test", "cmp", "and"]:
                                self.results.rundown_issues.append(RundownIssue(
                                    function=func_ea,
                                    function_name=func_name,
                                    address=head,
                                    issue_type="unchecked_rundown_acquire",
                                    details=f"ExAcquireRundownProtection return value not checked"
                                ))

    def find_double_fetch(self):
        """Find double fetch vulnerabilities"""
        print(f"[{PLUGIN_NAME}] Finding double fetch patterns...")

        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue

            func_name = self.get_func_name(func_ea)
            user_reads = []

            for head in idautils.FuncItems(func_ea):
                mnem = idc.print_insn_mnem(head)

                if mnem == "mov":
                    op0 = idc.print_operand(head, 0)
                    op1 = idc.print_operand(head, 1)

                    if "[" in op1:
                        user_reads.append((head, op1))

            for i, (addr1, op1) in enumerate(user_reads):
                for addr2, op2 in user_reads[i+1:]:
                    if op1 == op2 and addr2 - addr1 > 10:
                        self.results.toctou_candidates.append(TOCTOUCandidate(
                            function=func_ea,
                            function_name=func_name,
                            check_address=addr1,
                            use_address=addr2,
                            gap_instructions=addr2 - addr1,
                            check_type="memory_read",
                            use_type="memory_read_duplicate"
                        ))
                        break

    def find_callback_races(self):
        """Find callback registration/deregistration races"""
        print(f"[{PLUGIN_NAME}] Finding callback races...")

        callback_unregister = [
            "PsRemoveCreateThreadNotifyRoutine", "PsRemoveLoadImageNotifyRoutine",
            "CmUnRegisterCallback", "ObUnRegisterCallbacks", "FltUnregisterFilter"
        ]

        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue

            func_name = self.get_func_name(func_ea)
            has_register = False
            has_unregister = False

            for head in idautils.FuncItems(func_ea):
                mnem = idc.print_insn_mnem(head)
                if mnem == "call":
                    target = idc.get_operand_value(head, 0)
                    if target == idc.BADADDR:
                        continue
                    target_name = self.get_func_name(target)

                    if self.is_api_call(target_name, CALLBACK_REGISTER_FUNCTIONS):
                        has_register = True
                    if self.is_api_call(target_name, callback_unregister):
                        has_unregister = True

            # If we see unregister without proper synchronization
            if has_unregister:
                locks_used = self.results.function_locks.get(func_ea, [])
                if not locks_used:
                    self.results.rundown_issues.append(RundownIssue(
                        function=func_ea,
                        function_name=func_name,
                        address=func_ea,
                        issue_type="callback_unregister_race",
                        details="Callback unregistration without synchronization - callbacks may still be running"
                    ))

    def find_irp_races(self):
        """Find IRP completion races"""
        print(f"[{PLUGIN_NAME}] Finding IRP completion races...")

        irp_complete = ["IoCompleteRequest", "IofCompleteRequest"]
        irp_access = ["IoGetCurrentIrpStackLocation", "IoGetNextIrpStackLocation"]

        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue

            func_name = self.get_func_name(func_ea)
            complete_addr = None
            access_after_complete = []

            for head in idautils.FuncItems(func_ea):
                mnem = idc.print_insn_mnem(head)
                if mnem == "call":
                    target = idc.get_operand_value(head, 0)
                    if target == idc.BADADDR:
                        continue
                    target_name = self.get_func_name(target)

                    if self.is_api_call(target_name, irp_complete):
                        complete_addr = head
                    elif complete_addr and self.is_api_call(target_name, irp_access):
                        access_after_complete.append(head)

            if complete_addr and access_after_complete:
                self.results.rundown_issues.append(RundownIssue(
                    function=func_ea,
                    function_name=func_name,
                    address=access_after_complete[0],
                    issue_type="irp_access_after_complete",
                    details="IRP accessed after IoCompleteRequest - IRP may be freed"
                ))

    def find_pool_overflow(self):
        """Find potential pool buffer overflows"""
        print(f"[{PLUGIN_NAME}] Finding pool overflow patterns...")

        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue

            func_name = self.get_func_name(func_ea)
            alloc_info = {}  # Track allocations and their sizes

            for head in idautils.FuncItems(func_ea):
                mnem = idc.print_insn_mnem(head)
                if mnem == "call":
                    target = idc.get_operand_value(head, 0)
                    if target == idc.BADADDR:
                        continue
                    target_name = self.get_func_name(target)

                    # Track allocations
                    if self.is_api_call(target_name, ALLOC_FUNCTIONS):
                        size_arg = self._get_call_arg(head, 1)  # Size is usually 2nd arg
                        alloc_info[head] = size_arg

                    # Check copies with user-controlled size
                    if self.is_api_call(target_name, COPY_FUNCTIONS):
                        size_arg = self._get_call_arg(head, 2)  # Size is 3rd arg for memcpy
                        # If size comes from user input, flag it
                        if "InputBuffer" in size_arg or "UserBuffer" in size_arg:
                            self.results.toctou_candidates.append(TOCTOUCandidate(
                                function=func_ea,
                                function_name=func_name,
                                check_address=head,
                                use_address=head,
                                gap_instructions=0,
                                check_type="user_controlled_size",
                                use_type=f"memcpy with size: {size_arg}"
                            ))


# ============================================================
# HTTP API Server
# ============================================================

class RaceDetectorHandler(BaseHTTPRequestHandler):
    engine = None
    results = None

    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def _send_error(self, message, status=400):
        self._send_json({"error": message}, status)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        def get_param(name, default=None):
            vals = params.get(name, [default])
            return vals[0] if vals else default

        try:
            if path == "/status":
                self._send_json({
                    "status": "running",
                    "plugin": PLUGIN_NAME,
                    "port": HTTP_PORT,
                    "has_results": self.results is not None,
                    "hexrays_available": HAS_HEXRAYS
                })

            elif path == "/analyze":
                def do_analysis():
                    RaceDetectorHandler.engine = RaceDetectorEngine()
                    RaceDetectorHandler.results = RaceDetectorHandler.engine.run_full_analysis()

                idaapi.execute_sync(lambda: do_analysis(), idaapi.MFF_WRITE)
                self._send_json(self.results.to_dict() if self.results else {"error": "Analysis failed"})

            elif path == "/results":
                if not self.results:
                    self._send_error("No analysis results. Run /analyze first.")
                    return
                self._send_json(self.results.to_dict())

            elif path == "/summary":
                if not self.results:
                    self._send_error("No analysis results. Run /analyze first.")
                    return
                self._send_json(self.results.get_summary())

            elif path == "/races":
                if not self.results:
                    self._send_error("No analysis results. Run /analyze first.")
                    return
                severity = get_param("severity")
                races = self.results.race_candidates
                if severity:
                    races = [r for r in races if r.severity == severity]
                self._send_json([r.to_dict() for r in races])

            elif path == "/toctou":
                if not self.results:
                    self._send_error("No analysis results. Run /analyze first.")
                    return
                self._send_json([t.to_dict() for t in self.results.toctou_candidates])

            elif path == "/refcount":
                if not self.results:
                    self._send_error("No analysis results. Run /analyze first.")
                    return
                self._send_json([r.to_dict() for r in self.results.refcount_issues])

            elif path == "/rundown":
                if not self.results:
                    self._send_error("No analysis results. Run /analyze first.")
                    return
                self._send_json([r.to_dict() for r in self.results.rundown_issues])

            elif path == "/globals":
                if not self.results:
                    self._send_error("No analysis results. Run /analyze first.")
                    return
                self._send_json({hex(k): v for k, v in self.results.globals.items()})

            elif path == "/handlers":
                if not self.results:
                    self._send_error("No analysis results. Run /analyze first.")
                    return
                self._send_json({
                    "dispatch": {k: hex(v) for k, v in self.results.dispatch_handlers.items()},
                    "ioctl": {hex(k): hex(v) for k, v in self.results.ioctl_handlers.items()}
                })

            elif path == "/functions":
                limit = int(get_param("limit", "100"))
                offset = int(get_param("offset", "0"))
                query = get_param("query", "")

                functions = []
                for func_ea in idautils.Functions():
                    name = idc.get_name(func_ea)
                    if query and query.lower() not in (name or "").lower():
                        continue
                    functions.append({
                        "address": hex(func_ea),
                        "name": name or f"sub_{func_ea:X}"
                    })

                self._send_json(functions[offset:offset+limit])

            elif path == "/function":
                addr_str = get_param("address")
                if not addr_str:
                    self._send_error("Missing 'address' parameter")
                    return

                try:
                    addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                except:
                    self._send_error("Invalid address format")
                    return

                func = ida_funcs.get_func(addr)
                if not func:
                    self._send_error("No function at address")
                    return

                func_name = idc.get_name(func.start_ea)

                decompiled = None
                if HAS_HEXRAYS:
                    try:
                        cfunc = ida_hexrays.decompile(func.start_ea)
                        if cfunc:
                            decompiled = str(cfunc)
                    except:
                        pass

                disasm = []
                for head in idautils.FuncItems(func.start_ea):
                    disasm.append({
                        "address": hex(head),
                        "disasm": idc.GetDisasm(head)
                    })

                self._send_json({
                    "address": hex(func.start_ea),
                    "name": func_name,
                    "end": hex(func.end_ea),
                    "size": func.end_ea - func.start_ea,
                    "decompiled": decompiled,
                    "disassembly": disasm[:500]
                })

            elif path == "/decompile":
                addr_str = get_param("address")
                if not addr_str:
                    self._send_error("Missing 'address' parameter")
                    return

                try:
                    addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                except:
                    self._send_error("Invalid address format")
                    return

                if not HAS_HEXRAYS:
                    self._send_error("Hex-Rays decompiler not available")
                    return

                try:
                    cfunc = ida_hexrays.decompile(addr)
                    if cfunc:
                        self._send_json({"decompiled": str(cfunc)})
                    else:
                        self._send_error("Decompilation failed")
                except Exception as e:
                    self._send_error(f"Decompilation error: {str(e)}")

            elif path == "/xrefs":
                addr_str = get_param("address")
                if not addr_str:
                    self._send_error("Missing 'address' parameter")
                    return

                try:
                    addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                except:
                    self._send_error("Invalid address format")
                    return

                xrefs_to = []
                for xref in idautils.XrefsTo(addr):
                    xrefs_to.append({
                        "from": hex(xref.frm),
                        "type": ida_xref.get_xref_type_name(xref.type)
                    })

                xrefs_from = []
                for xref in idautils.XrefsFrom(addr):
                    xrefs_from.append({
                        "to": hex(xref.to),
                        "type": ida_xref.get_xref_type_name(xref.type)
                    })

                self._send_json({
                    "address": hex(addr),
                    "xrefs_to": xrefs_to[:100],
                    "xrefs_from": xrefs_from[:100]
                })

            elif path == "/search":
                query = get_param("query")
                if not query:
                    self._send_error("Missing 'query' parameter")
                    return

                results = []
                for func_ea in idautils.Functions():
                    name = idc.get_name(func_ea)
                    if name and query.lower() in name.lower():
                        results.append({
                            "address": hex(func_ea),
                            "name": name
                        })
                        if len(results) >= 100:
                            break

                self._send_json(results)

            elif path == "/strings":
                query = get_param("filter", "")
                limit = int(get_param("limit", "100"))

                strings = []
                for s in idautils.Strings():
                    str_val = str(s)
                    if query.lower() in str_val.lower():
                        strings.append({
                            "address": hex(s.ea),
                            "value": str_val,
                            "length": s.length
                        })
                        if len(strings) >= limit:
                            break

                self._send_json(strings)

            elif path == "/goto":
                addr_str = get_param("address")
                if not addr_str:
                    self._send_error("Missing 'address' parameter")
                    return

                try:
                    addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                except:
                    self._send_error("Invalid address format")
                    return

                idaapi.execute_sync(lambda: ida_kernwin.jumpto(addr), idaapi.MFF_FAST)
                self._send_json({"success": True, "jumped_to": hex(addr)})

            elif path == "/imports":
                imports = []
                for i in range(ida_nalt.get_import_module_qty()):
                    module_name = ida_nalt.get_import_module_name(i)
                    def imp_cb(ea, name, ordinal):
                        imports.append({
                            "address": hex(ea),
                            "name": name,
                            "module": module_name,
                            "ordinal": ordinal
                        })
                        return True
                    ida_nalt.enum_import_names(i, imp_cb)
                self._send_json(imports)

            elif path == "/exports":
                exports = []
                for i, ordinal, ea, name in idautils.Entries():
                    exports.append({
                        "index": i,
                        "ordinal": ordinal,
                        "address": hex(ea),
                        "name": name
                    })
                self._send_json(exports)

            elif path == "/segments":
                segments = []
                for seg_ea in idautils.Segments():
                    seg = ida_segment.getseg(seg_ea)
                    segments.append({
                        "start": hex(seg_ea),
                        "end": hex(ida_segment.get_segm_end(seg_ea)),
                        "name": ida_segment.get_segm_name(seg),
                        "size": ida_segment.get_segm_end(seg_ea) - seg_ea
                    })
                self._send_json(segments)

            elif path == "/help":
                self._send_json({
                    "endpoints": {
                        "/status": "Check server status",
                        "/analyze": "Run full race condition analysis",
                        "/results": "Get full analysis results",
                        "/summary": "Get analysis summary",
                        "/races?severity=critical|high|medium": "Get race candidates",
                        "/toctou": "Get TOCTOU candidates",
                        "/refcount": "Get refcount issues",
                        "/rundown": "Get rundown protection issues",
                        "/globals": "Get global variables",
                        "/handlers": "Get dispatch/IOCTL handlers",
                        "/functions?limit=100&offset=0&query=...": "List functions",
                        "/function?address=0x...": "Get function info + decompilation",
                        "/decompile?address=0x...": "Decompile function",
                        "/xrefs?address=0x...": "Get cross-references",
                        "/search?query=...": "Search functions by name",
                        "/strings?filter=...&limit=100": "Search strings",
                        "/goto?address=0x...": "Jump to address in IDA",
                        "/imports": "List imports",
                        "/exports": "List exports",
                        "/segments": "List segments"
                    }
                })

            else:
                self._send_error(f"Unknown endpoint: {path}", 404)

        except Exception as e:
            import traceback
            self._send_error(f"Internal error: {str(e)}\n{traceback.format_exc()}", 500)


class RaceDetectorServer:
    def __init__(self, port=HTTP_PORT):
        self.port = port
        self.server = None
        self.thread = None

    def start(self):
        try:
            self.server = HTTPServer(("127.0.0.1", self.port), RaceDetectorHandler)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            print(f"[{PLUGIN_NAME}] HTTP server started on http://127.0.0.1:{self.port}")
            print(f"[{PLUGIN_NAME}] Use /help endpoint for API documentation")
            return True
        except Exception as e:
            print(f"[{PLUGIN_NAME}] Failed to start server: {e}")
            return False

    def stop(self):
        if self.server:
            self.server.shutdown()
            print(f"[{PLUGIN_NAME}] HTTP server stopped")


# ============================================================
# IDA Plugin Interface
# ============================================================

class RaceDetectorPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Windows Driver Race Condition Detector"
    help = "Detects potential race conditions in Windows kernel drivers"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    server = None

    def init(self):
        print(f"[{PLUGIN_NAME}] Plugin loaded")
        self.server = RaceDetectorServer()
        self.server.start()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.show_ui()

    def term(self):
        if self.server:
            self.server.stop()
        print(f"[{PLUGIN_NAME}] Plugin unloaded")

    def show_ui(self):
        result = ida_kernwin.ask_buttons(
            "Analyze",
            "View Results",
            "Cancel",
            1,
            f"{PLUGIN_NAME}\n\n"
            f"HTTP API running on http://127.0.0.1:{HTTP_PORT}\n\n"
            "Choose action:"
        )

        if result == 1:
            engine = RaceDetectorEngine()
            results = engine.run_full_analysis()
            RaceDetectorHandler.results = results

            summary = results.get_summary()

            msg = f"""Analysis Complete!

Globals Found: {summary['total_globals']}
Dispatch Handlers: {summary['total_dispatch_handlers']}
IOCTL Handlers: {summary['total_ioctl_handlers']}

Race Candidates:
  - Critical: {summary['critical_races']}
  - High: {summary['high_races']}
  - Medium: {summary['medium_races']}

Other Issues:
  - TOCTOU: {summary['toctou_issues']}
  - Refcount: {summary['refcount_issues']}
  - Rundown: {summary['rundown_issues']}

Access full results via HTTP API:
  http://127.0.0.1:{HTTP_PORT}/results
"""
            ida_kernwin.info(msg)

        elif result == 0:
            if RaceDetectorHandler.results:
                import webbrowser
                webbrowser.open(f"http://127.0.0.1:{HTTP_PORT}/results")
            else:
                ida_kernwin.warning("No results yet. Run analysis first.")


def PLUGIN_ENTRY():
    return RaceDetectorPlugin()
