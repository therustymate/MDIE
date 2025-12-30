# **MDAV Scan Characteristics Analysis Report (Based on ProcMon64 Logs)**

---

## **1. Overview**
This report analyzes the file system and registry activities of the **Microsoft Defender Antivirus (MsMpEng.exe)** process captured via ProcMon64 logs (`MDAVCustomScan.CSV`).  
Analysis timeframe: **2025-12-30 18:12:14.114 – 18:12:14.288 (~0.17 seconds)**

---

## **2. Key Findings**

### **2.1. Scan Target File Types**
MDAV primarily scans **system DLLs and executable files**, along with user documents, GitHub repositories, cache files, and more.

- **System DLLs**:
  - `C:\Windows\System32\*.dll` (e.g., `mpr.dll`, `ntlanman.dll`, `winsta.dll`)
  - `C:\ProgramData\Microsoft\Windows Defender\Platform\*\*.dll`
- **GitHub Repositories**:
  - `C:\Users\rusty\Documents\GitHub\therustymate.github.io\` (static site files)
  - `C:\Users\rusty\Documents\GitHub\Opera\` (security research project)
- **Cache/Database Files**:
  - `C:\ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db-shm`
  - `C:\Users\rusty\AppData\LocalLow\Intel\ShaderCache\*`

Manual Analysis Note: Scanning 'system' executable files seems to be an integrity check process.

---

### **2.2. MDAV Scan Behavior Patterns**

#### **2.2.1. File Opening Methods**
1. **First Open**:  
   `Desired Access: Read Attributes` + `Options: Open For Backup, Open Reparse Point, Open Requiring Oplock`  
   → Only reads file attributes and metadata.

2. **Second Open**:  
   `Desired Access: Read Attributes` + `Options: Synchronous IO Non-Alert, Open For Backup, Open No Recall, Disallow Exclusive`  
   → Prepares for actual content inspection.

3. **FileSystemControl Calls**:  
   - `FSCTL_REQUEST_OPLOCK` → Requests oplock and immediately closes (`OPLOCK HANDLE CLOSED`)
   - `FSCTL_READ_FILE_USN_DATA` → Checks change history in USN journal

#### **2.2.2. Metadata Queries**
- `QueryAllInformationFile` → `BUFFER OVERFLOW` (file info larger than buffer)
- `QueryInformationVolume` → Volume information check (creation time, serial number)
- `QueryIdInformation` → File identifier verification

#### **2.2.3. Directory Enumeration**
- `QueryDirectory` calls recursively scan all subfolders/files
- Uses `FileInformationClass: FileFullDirectoryInformation`

---

### **2.3. Registry Activity**
MDAV queries the registry to check scan settings and policies.

- **Main Query Keys**:
  ```
  HKLM\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatIDDefaultAction
  HKLM\SOFTWARE\Microsoft\Windows Defender\Scan
  HKLM\SOFTWARE\Microsoft\Windows Defender\InstallLocation
  ```
- **Policy Checks**:
  - `ThrottleForScheduledScanOnly`
  - `ScanOnlyIfIdleEnabled`
  - `EnableLowCPUPriority`

---

### **2.4. Memory Mapping & File Locking**
- `CreateFileMapping` → `FILE LOCKED WITH ONLY READERS`  
  → Maps files as read-only for efficient scanning
- `LockFile`/`UnlockFileSingle` → Uses exclusive/shared locks on database files (`.db-shm`)

---

## **3. Scan Optimization & Efficiency Features**

1. **Oplock Usage**: Requests oplocks to avoid exclusive file access, then immediately releases them
2. **USN Journal Utilization**: Quickly identifies changed files via Update Sequence Number journal
3. **Memory Mapping**: Scans via memory mapping instead of direct file reading for speed
4. **Recursive Directory Enumeration**: Rapidly scans entire directory trees
5. **Settings/Policy Caching**: Reads and caches registry policies once for performance

---

## **4. Security/Privacy Observations**

### **4.1. Sensitive Paths Included in Scan**
- Entire user GitHub repositories
- Intel ShaderCache and other app data
- Version control files including `.git` directories

### **4.2. Non-Executable Files Also Scanned**
- Image files (`.png`, `.jpg`), CSS, JS, Markdown files, etc.  
  → Likely for detecting potential malicious code or exploits

---

## **5. Conclusions & Implications**

- **Layered Approach**: Metadata → USN journal → actual content (progressive inspection)
- **Least Privilege Principle**: Uses minimal file access permissions where possible
- **Performance Optimization**: Leverages oplocks, memory mapping, and caching

---

## **6. Future Research Directions**
- Analyze **MDAV Heuristic Scanning Patterns**
- Study interactions with **Cloud-delivered Protection**
- In-depth behavioral analysis via **ETW (Event Tracing for Windows)**

---

**Analyst:** AI Security Researcher (DeepSeek)
**Analysis Date:** December 30, 2025  
**Data Source:** `MDAVCustomScan.CSV` (ProcMon64 capture)