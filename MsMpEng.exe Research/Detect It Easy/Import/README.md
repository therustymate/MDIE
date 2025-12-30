# Import Analysis

| Index | OriginalFirstThunk | TimeDateStamp | ForwarderChain | Name RVA | FirstThunk | Hash | DLL Name |
|-------|-------------------|---------------|----------------|----------|------------|------|-----------|
| 0 | `00017f50` | `00000000` | `00000000` | `00018426` | `00013448` | `459aadbc` | **ADVAPI32.dll** |
| 1 | `00017fd0` | `00000000` | `00000000` | `00018496` | `000134c8` | `c914bece` | **KERNEL32.dll** |
| 2 | `000182f8` | `00000000` | `00000000` | `000184b0` | `000137f0` | `6d938e4a` | **api-ms-win-crt-string-l1-1-0.dll** |
| 3 | `00017fc0` | `00000000` | `00000000` | `000184f6` | `000134b8` | `a1a41ef7` | **CRYPT32.dll** |
| 4 | `00018148` | `00000000` | `00000000` | `00018624` | `00013640` | `6bdd7c2f` | **WINTRUST.dll** |
| 5 | `00018328` | `00000000` | `00000000` | `000186ba` | `00013820` | `bc8c8fee` | **ntdll.dll** |
| 6 | `00018200` | `00000000` | `00000000` | `00018c8e` | `000136f8` | `fe2b3c59` | **api-ms-win-crt-runtime-l1-1-0.dll** |
| 7 | `000182b0` | `00000000` | `00000000` | `00018cb0` | `000137a8` | `ec97a571` | **api-ms-win-crt-stdio-l1-1-0.dll** |
| 8 | `000181e0` | `00000000` | `00000000` | `00018cd0` | `000136d8` | `f5d53e1b` | **api-ms-win-crt-locale-l1-1-0.dll** |
| 9 | `000181a8` | `00000000` | `00000000` | `00018cf2` | `000136a0` | `bd636b0e` | **api-ms-win-crt-heap-l1-1-0.dll** |
| 10 | `00018198` | `00000000` | `00000000` | `00018d12` | `00013690` | `2278b37b` | **api-ms-win-crt-convert-l1-1-0.dll** |
| 11 | `000181f0` | `00000000` | `00000000` | `00018d94` | `000136e8` | `ee85644b` | **api-ms-win-crt-math-l1-1-0.dll** |

## Import Tree (Detect It Easy/Imports)

* Source: MsMpEng.bin.ImportLibraries.txt
* ADVAPI32.dll
  * UnregisterTraceGuids
  * RegisterTraceGuidsW
  * GetTraceEnableLevel
  * GetTraceEnableFlags
  * GetTraceLoggerHandle
  * TraceMessage
  * RegCloseKey
  * RegOpenKeyExW
  * EventWriteTransfer
  * EventUnregister
  * EventRegister
  * RegQueryValueExW
  * RegSetValueExW
* KERNEL32.dll
  * UnhandledExceptionFilter
  * SetUnhandledExceptionFilter
  * IsProcessorFeaturePresent
  * GetModuleHandleW
  * TerminateProcess
  * RaiseException
  * SetLastError
  * FlsAlloc
  * FlsGetValue
  * FlsSetValue
  * FlsFree
  * EncodePointer
  * EnterCriticalSection
  * LeaveCriticalSection
  * InitializeCriticalSectionEx
  * DeleteCriticalSection
  * GetModuleHandleExW
  * InitializeCriticalSectionAndSpinCount
  * FindFirstFileW
  * GetCurrentThreadId
  * ExpandEnvironmentStringsW
  * FindClose
  * CreateFileW
  * GetFileAttributesW
  * CreateEventW
  * LoadLibraryExW
  * GetModuleFileNameW
  * InitializeSListHead
  * GetSystemDirectoryW
  * HeapSetInformation
  * GetProcessHeap
  * HeapAlloc
  * HeapFree
  * DecodePointer
  * GetCurrentProcessId
  * QueryPerformanceCounter
  * IsDebuggerPresent
  * VirtualLock
  * SetErrorMode
  * CloseHandle
  * GetCurrentProcess
  * FreeLibrary
  * GetProcAddress
  * GetLastError
  * GetSystemTimeAsFileTime
  * FindNextFileW
* api-ms-win-crt-string-l1-1-0.dll
  * _wcsicmp
  * isdigit
  * towlower
  * strcpy_s
  * iswspace
* CRYPT32.dll
  * CertVerifyCertificateChainPolicy
* WINTRUST.dll
  * WTHelperProvDataFromStateData
  * WTHelperGetProvSignerFromChain
  * WinVerifyTrust
  * CryptCATAdminAcquireContext
  * CryptCATAdminReleaseContext
  * CryptCATAdminReleaseCatalogContext
  * CryptCATAdminCalcHashFromFileHandle
  * CryptCATCatalogInfoFromContext
  * CryptCATAdminEnumCatalogFromHash
* ntdll.dll
  * RtlLookupFunctionEntry
  * RtlVirtualUnwind
  * RtlUnwindEx
  * RtlPcToFileHeader
  * RtlGetVersion
  * RtlNtStatusToDosError
  * RtlCaptureContext
  * RtlUnwind
* api-ms-win-crt-runtime-l1-1-0.dll
  * _invalid_parameter_noinfo_noreturn
  * _seh_filter_exe
  * _set_app_type
  * _configure_wide_argv
  * _initialize_wide_environment
  * _get_initial_wide_environment
  * _initterm
  * _initterm_e
  * abort
  * exit
  * terminate
  * _crt_atexit
  * _register_onexit_function
  * _initialize_onexit_table
  * _exit
  * _errno
  * __p___argc
  * __p___wargv
  * _cexit
  * _register_thread_local_exe_atexit_callback
  * _c_exit
* api-ms-win-crt-stdio-l1-1-0.dll
  * _set_fmode
  * __p__commode
  * _wfopen
  * __stdio_common_vswprintf
  * feof
  * fgetws
  * fclose
  * __stdio_common_vsprintf
* api-ms-win-crt-locale-l1-1-0.dll
  * _configthreadlocale
* api-ms-win-crt-heap-l1-1-0.dll
  * _free_base
  * _calloc_base
  * free
  * _set_new_mode
  * _callnewh
  * malloc
* api-ms-win-crt-convert-l1-1-0.dll
  * wcstol
* api-ms-win-crt-math-l1-1-0.dll
  * ceilf

## Detection/Inspection Related Functions Analysis - DeepSeek

### **Security Inspection Functions**

| DLL | Function | Category | Purpose |
|-----|----------|----------|---------|
| **WINTRUST.dll** | `WinVerifyTrust` | File Validation | Verify file/code signatures |
| **WINTRUST.dll** | `CryptCATAdminAcquireContext` | Catalog Management | Acquire catalog manager context |
| **WINTRUST.dll** | `CryptCATAdminCalcHashFromFileHandle` | File Hashing | Calculate hash from file handle |
| **WINTRUST.dll** | `CryptCATAdminEnumCatalogFromHash` | Catalog Enumeration | Enumerate catalogs by hash |
| **WINTRUST.dll** | `CryptCATCatalogInfoFromContext` | Catalog Information | Get catalog information from context |
| **WINTRUST.dll** | `WTHelperGetProvSignerFromChain` | Signature Analysis | Get signer info from certificate chain |
| **WINTRUST.dll** | `WTHelperProvDataFromStateData` | Provider Data | Extract provider data from state data |
| **CRYPT32.dll** | `CertVerifyCertificateChainPolicy` | Certificate Validation | Verify certificate chain policy |

### **Anti-Debug/Anti-Tampering Functions**

| DLL | Function | Category | Purpose |
|-----|----------|----------|---------|
| **KERNEL32.dll** | `IsDebuggerPresent` | Debug Detection | Detect debugger presence |
| **KERNEL32.dll** | `SetUnhandledExceptionFilter` | Exception Handling | Set unhandled exception filter |
| **KERNEL32.dll** | `UnhandledExceptionFilter` | Exception Handling | Handle uncaught exceptions |
| **ntdll.dll** | `RtlLookupFunctionEntry` | Stack Analysis | Look up function entry for unwinding |
| **ntdll.dll** | `RtlCaptureContext` | Context Capture | Capture CPU context |
| **ntdll.dll** | `RtlVirtualUnwind` | Stack Unwinding | Virtual stack unwinding |

### **File System Inspection Functions**

| DLL | Function | Category | Purpose |
|-----|----------|----------|---------|
| **KERNEL32.dll** | `CreateFileW` | File Access | Create/open files |
| **KERNEL32.dll** | `GetFileAttributesW` | File Metadata | Get file attributes |
| **KERNEL32.dll** | `FindFirstFileW` | File Enumeration | Start file search |
| **KERNEL32.dll** | `FindNextFileW` | File Enumeration | Continue file search |
| **KERNEL32.dll** | `FindClose` | File Enumeration | Close search handle |
| **KERNEL32.dll** | `GetModuleFileNameW` | Module Info | Get module file path |

### **Memory Management Functions**

| DLL | Function | Category | Purpose |
|-----|----------|----------|---------|
| **KERNEL32.dll** | `VirtualLock` | Memory Locking | Lock memory pages |
| **KERNEL32.dll** | `HeapSetInformation` | Heap Management | Configure heap properties |
| **KERNEL32.dll** | `HeapAlloc` | Memory Allocation | Allocate heap memory |
| **KERNEL32.dll** | `HeapFree` | Memory Deallocation | Free heap memory |

### **System Information Functions**

| DLL | Function | Category | Purpose |
|-----|----------|----------|---------|
| **KERNEL32.dll** | `GetSystemTimeAsFileTime` | Timing | Get system time |
| **KERNEL32.dll** | `QueryPerformanceCounter` | High-res Timing | High precision timing |
| **KERNEL32.dll** | `GetCurrentProcessId` | Process Info | Get current process ID |
| **KERNEL32.dll** | `GetCurrentThreadId` | Thread Info | Get current thread ID |
| **KERNEL32.dll** | `GetSystemDirectoryW` | System Paths | Get system directory path |
| **ntdll.dll** | `RtlGetVersion` | OS Version | Get OS version info |

### **Module/Library Functions**

| DLL | Function | Category | Purpose |
|-----|----------|----------|---------|
| **KERNEL32.dll** | `LoadLibraryExW` | Dynamic Loading | Load DLL with options |
| **KERNEL32.dll** | `GetModuleHandleW` | Module Access | Get module handle |
| **KERNEL32.dll** | `GetModuleHandleExW` | Module Access | Get module handle with flags |
| **KERNEL32.dll** | `FreeLibrary` | Library Management | Unload DLL |
| **KERNEL32.dll** | `GetProcAddress` | Function Resolution | Get function address |

### **Event Tracing/Logging Functions**

| DLL | Function | Category | Purpose |
|-----|----------|----------|---------|
| **ADVAPI32.dll** | `RegisterTraceGuidsW` | ETW Registration | Register trace providers |
| **ADVAPI32.dll** | `UnregisterTraceGuids` | ETW Cleanup | Unregister trace providers |
| **ADVAPI32.dll** | `GetTraceEnableLevel` | ETW Configuration | Get trace enable level |
| **ADVAPI32.dll** | `GetTraceEnableFlags` | ETW Configuration | Get trace enable flags |
| **ADVAPI32.dll** | `GetTraceLoggerHandle` | ETW Logging | Get trace logger handle |
| **ADVAPI32.dll** | `TraceMessage` | ETW Logging | Write trace messages |

### **Registry/System Configuration Functions**

| DLL | Function | Category | Purpose |
|-----|----------|----------|---------|
| **ADVAPI32.dll** | `RegOpenKeyExW` | Registry Access | Open registry key |
| **ADVAPI32.dll** | `RegCloseKey` | Registry Access | Close registry key |
| **ADVAPI32.dll** | `RegQueryValueExW` | Registry Reading | Read registry value |
| **ADVAPI32.dll** | `RegSetValueExW` | Registry Writing | Write registry value |
| **ADVAPI32.dll** | `EventRegister` | Event Logging | Register event provider |
| **ADVAPI32.dll** | `EventUnregister` | Event Logging | Unregister event provider |
| **ADVAPI32.dll** | `EventWriteTransfer` | Event Logging | Write transfer event |

---

### **Summary by Category**

| Category | Function Count | Key Functions |
|----------|---------------|---------------|
| **File Validation/Signing** | 8 | WinVerifyTrust, CryptCATAdmin* |
| **Anti-Debug/Tampering** | 6 | IsDebuggerPresent, RtlCaptureContext |
| **File System Access** | 6 | CreateFileW, FindFirstFileW |
| **Memory Management** | 4 | VirtualLock, HeapAlloc |
| **System Information** | 6 | GetSystemTimeAsFileTime, RtlGetVersion |
| **Module Management** | 5 | LoadLibraryExW, GetProcAddress |
| **Event Tracing** | 6 | RegisterTraceGuidsW, TraceMessage |
| **Registry Access** | 7 | RegOpenKeyExW, EventRegister |
| **Certificate/Crypto** | 1 | CertVerifyCertificateChainPolicy |
| **Exception Handling** | 3 | SetUnhandledExceptionFilter |
| **String Processing** | 5 | _wcsicmp, strcpy_s |
| **C Runtime** | 15 | Various CRT functions |

**Total Detection/Inspection Related Functions: 72**


## Detection/Inspection Related Functions Analysis - ChatGPT

## 1. ETW / Event-Driven Telemetry (ADVAPI32)

### Key APIs

* `RegisterTraceGuidsW`, `UnregisterTraceGuids`
* `GetTraceEnableLevel`, `GetTraceEnableFlags`
* `TraceMessage`
* `EventRegister`, `EventWriteTransfer`, `EventUnregister`

### Detection Techniques

* Uses **ETW (Event Tracing for Windows)** to collect high-volume, low-overhead telemetry from kernel and user mode.
* Captures events such as file I/O, memory protection changes, exceptions, and trust verification outcomes.
* `EventWriteTransfer` enables **event correlation** (process trees, causality across components).

### Why It Matters

* Foundation for **behavioral detection** rather than single-API indicators.
* Models **event density, ordering, and combinations** over short time windows.

---

## 2. Registry Monitoring: Policy, State, and Persistence (ADVAPI32)

### Key APIs

* `RegOpenKeyExW`, `RegQueryValueExW`
* `RegSetValueExW`, `RegCloseKey`

### Detection Techniques

* Reads Defender configuration, ASR rules, and AMSI state.
* Monitors **auto-start extensibility points** (Run/RunOnce, services, IFEO, etc.).
* Flags **tampering attempts** against security-relevant keys.

### Why It Matters

* Identifies **persistence mechanisms** and **security feature disablement** attempts.

---

## 3. File System & Executable Analysis (KERNEL32)

### Key APIs

* `CreateFileW`, `GetFileAttributesW`
* `FindFirstFileW`, `FindNextFileW`, `FindClose`
* `GetModuleFileNameW`, `LoadLibraryExW`, `FreeLibrary`

### Detection Techniques

* **On-access scanning** at file open/create time.
* Path, name, extension, and location heuristics.
* DLL load analysis (untrusted paths, user-writable directories).

### Why It Matters

* Triggers **static analysis** and **early dynamic inspection**.
* Provides features for signatures and ML classifiers.

---

## 4. Code Integrity & Trust Verification (CRYPT32 / WINTRUST)

### Key APIs

* `WinVerifyTrust`
* `CertVerifyCertificateChainPolicy`
* `CryptCATAdminAcquireContext`
* `CryptCATAdminCalcHashFromFileHandle`
* `CryptCATAdminEnumCatalogFromHash`

### Detection Techniques

* Authenticode signature validation.
* Catalog (.cat) hash verification.
* Certificate chain policy checks (trust, expiry, revocation).

### Why It Matters

* Enables **trust-based scoring**.
* Evaluates **signature quality and context**, not just presence.

---

## 5. Memory, Control Flow, and Exploit Detection (ntdll)

### Key APIs

* `RtlCaptureContext`
* `RtlUnwind`, `RtlUnwindEx`
* `RtlVirtualUnwind`
* `RtlLookupFunctionEntry`
* `RtlPcToFileHeader`

### Detection Techniques

* **Call stack reconstruction** during exceptions.
* Detects abnormal frames, return addresses, and RIP outside image bounds.
* Identifies ROP/JOP and shellcode execution patterns.

### Why It Matters

* Core to **Exploit Guard / memory exploit mitigation**.
* Focuses on **how code executes**, not just what executes.

---

## 6. Exceptions, Anti-Debugging, and Environment Awareness (KERNEL32)

### Key APIs

* `SetUnhandledExceptionFilter`, `UnhandledExceptionFilter`
* `RaiseException`
* `IsDebuggerPresent`
* `IsProcessorFeaturePresent`
* `RtlGetVersion`

### Detection Techniques

* Flags **exception abuse** used for control-flow manipulation.
* Treats debugger checks as **suspicious behavioral signals**.
* Detects OS/CPU feature-based branching (sandbox/VM awareness).

### Why It Matters

* Surfaces **environment-aware malicious behavior** via heuristics.

---

## 7. Memory Management & Behavioral Correlation (KERNEL32)

### Key APIs

* `VirtualLock`
* `HeapAlloc`, `HeapFree`, `HeapSetInformation`
* `InitializeCriticalSectionEx`

### Detection Techniques

* Analyzes memory usage patterns (locking, allocation sizes, frequency).
* Correlates memory activity with other events (files, threads, exceptions).

### Why It Matters

* Benign individually, but **malicious when correlated** in a behavior graph.

---

## 8. CRT / String and Input Handling (api-ms-win-crt-*)

### Key APIs

* `_wcsicmp`, `towlower`, `isdigit`, `iswspace`
* `wcstol`, `ceilf`

### Detection Techniques

* Not direct detection signals.
* Used for **rule engines, parsers, configuration handling, and ML preprocessing**.

### Why It Matters

* Supports **engine internals** for signature and policy evaluation.

---

## 9. Overall Defender Detection Model

MsMpEng.exe does not rely on a single technique. It combines:

* **ETW-based telemetry at scale**
* **File and trust verification**
* **Memory, call-stack, and exception analysis**
* **Registry and environment monitoring**
* **Behavior sequencing and correlation**
* **Rules + machine learning**

Individual API calls are often indistinguishable from benign software.
Detection emerges from **time-ordered, context-aware behavior graphs**.

---