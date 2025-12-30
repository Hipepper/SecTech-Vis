
export enum Category {
  HOME = 'HOME',
  BINARY = 'BINARY',
  WEB = 'WEB',
  ADVERSARIAL = 'ADVERSARIAL',
  ALGORITHM = 'ALGORITHM'
}

export enum ExploitType {
  STACK = 'STACK',
  HEAP = 'HEAP',
  UAF = 'UAF',
  FORMAT_STRING = 'FORMAT_STRING',
  INTEGER_OVERFLOW = 'INTEGER_OVERFLOW',
  DOUBLE_FREE = 'DOUBLE_FREE',
  ROP = 'ROP',
  HEAVENS_GATE = 'HEAVENS_GATE',
  REFLECTIVE_DLL = 'REFLECTIVE_DLL',
  PROCESS_HOLLOWING = 'PROCESS_HOLLOWING',
  THREAD_HIJACKING = 'THREAD_HIJACKING',
  SQLI = 'SQLI',
  SSRF = 'SSRF',
  CSRF = 'CSRF',
  LOG4SHELL = 'LOG4SHELL',
  NEXTJS_RCE = 'NEXTJS_RCE',
  XXE = 'XXE',
  XSS = 'XSS',
  FILE_UPLOAD = 'FILE_UPLOAD',
  PATH_TRAVERSAL = 'PATH_TRAVERSAL',
  DESERIALIZATION = 'DESERIALIZATION',
  FASTJSON = 'FASTJSON',
  AES = 'AES',
  NETWORK_MAPPING = 'NETWORK_MAPPING',
  WAF = 'WAF',
  IPS = 'IPS',
  CFW = 'CFW'
}

export enum Language {
  EN = 'EN',
  ZH = 'ZH'
}

export enum Architecture {
  X86 = 'x86',
  X64 = 'x64',
  ARM = 'ARM',
  MIPS = 'MIPS'
}

export interface AnimationStep {
  id: number;
  title: string;
  description: string;
  codeHighlight: number[];
  // Existing fields...
  stackBufferContent?: string;
  stackEBPContent?: string;
  stackRetContent?: string;
  stackInstructionPointer?: string;
  heapChunk1Content?: string;
  heapChunk1Header?: string;
  heapChunk2Header?: string;
  heapChunk2Content?: string;
  uafSlotState?: 'empty' | 'objA' | 'free' | 'objB';
  uafPtr1State?: 'null' | 'pointing';
  uafPtr2State?: 'null' | 'pointing';
  uafData?: string;
  fmtStackValues?: string[];
  fmtOutput?: string;
  fmtReadIndex?: number;
  intMathA?: number;
  intMathB?: number;
  intMathResult?: number;
  intMathReal?: number;
  intBufferState?: 'none' | 'small' | 'overflow';
  dfChunkState?: 'alloc' | 'free' | 'double_free' | 'overlap';
  dfBinList?: string[];
  dfPtr1?: string;
  dfPtr2?: string;
  dfPtr3?: string;
  ropStack?: { label: string, value: string, type: 'padding'|'gadget'|'data'|'target', active?: boolean }[];
  ropRegs?: { rip: string, rdi: string, rsp: string };
  ropAction?: 'overflow' | 'ret' | 'pop' | 'exec';
  hgMode?: 'x86' | 'x64';
  hgCS?: string;
  hgRegs?: { ax: string; ip: string; sp: string; };
  hgInstruction?: string;
  rdllState?: 'idle' | 'alloc' | 'write' | 'boot' | 'reloc' | 'imports' | 'exec';
  rdllInjector?: { action: string, active: boolean };
  rdllTarget?: { memory: { label: string, type: 'free' | 'dll_raw' | 'dll_mapped', active?: boolean, highlight?: boolean }[], threadStatus: string };
  phState?: 'idle' | 'create' | 'unmap' | 'alloc' | 'write' | 'resume';
  phTarget?: { name: string; status: 'Running' | 'Suspended' | 'Hollowed'; memoryContent: 'LegitCode' | 'Empty' | 'MalPayload'; entryPoint: string; };
  thState?: 'running' | 'suspend' | 'inject' | 'context' | 'resume';
  thThread?: { id: number; status: 'Running' | 'Suspended'; rip: string; codeBlock: 'Legit' | 'Shellcode'; };
  sqliStep?: 'input' | 'request' | 'query' | 'db' | 'response';
  sqliInput?: string;
  sqliUrl?: string;
  sqliQuery?: string;
  sqliHighlight?: string;
  sqliDbResult?: { id: number, user: string, role: string }[];
  ssrfStep?: 'input' | 'request_out' | 'processing' | 'request_in' | 'response_internal' | 'response_final';
  ssrfUrl?: string;
  ssrfPayload?: string;
  ssrfInternalData?: string;
  csrfStep?: 'login' | 'visit_malicious' | 'auto_request' | 'cookie_attach' | 'server_process';
  csrfCookie?: boolean;
  csrfTab?: 'bank' | 'evil';
  csrfBalance?: number;
  l4sStep?: 'input' | 'logging' | 'lookup' | 'ldap_req' | 'ldap_res' | 'class_download' | 'rce';
  l4sPayload?: string;
  nextRceStep?: 'craft_payload' | 'send_poison' | 'cache_write' | 'trigger_render' | 'cache_hit' | 'deserialization' | 'execution';
  nextRcePayload?: string;
  xxeStep?: 'input' | 'parse' | 'resolve' | 'access' | 'response';
  xxePayload?: string;
  xxeFileContent?: string;
  xssStep?: 'inject' | 'store' | 'victim_load' | 'execute' | 'exfiltrate';
  xssPayload?: string;
  xssCookie?: string;
  deserStep?: 'craft' | 'send' | 'parse' | 'magic_method' | 'rce';
  deserPayload?: string;
  deserObjState?: string;
  // Fastjson specific
  fjsonStep?: 'input' | 'parsing' | 'template_injection' | 'getvalue' | 'template_eval' | 'rce';
  fjsonPayload?: string;
  fjsonJsonStr?: string;
  fjsonValue?: string;
  fjsonTemplate?: string;
  fjsonOutput?: string;
  // File Upload specific
  fuStep?: 'input' | 'upload' | 'store' | 'web_access' | 'execute';
  fuFilename?: string;
  fuTmpPath?: string;
  fuSavePath?: string;
  fuMime?: string;
  fuWebUrl?: string;
  // Path Traversal specific
  ptStep?: 'input' | 'request' | 'normalize' | 'resolve' | 'read' | 'response';
  ptBasePath?: string;
  ptInputPath?: string;
  ptNormalizedPath?: string;
  ptFinalPath?: string;
  ptFileContent?: string;
  aesState?: 'key_expansion' | 'round_0' | 'rounds_main' | 'round_final' | 'output';
  aesMatrix?: string[];
  aesRoundKey?: string[];
  aesOperation?: 'subbytes' | 'shiftrows' | 'mixcolumns' | 'addroundkey' | 'expand' | 'none';
  aesRound?: number;
  aesHighlight?: 'key' | 'sbox' | 'row' | 'col' | 'none';
  // Mapping / WAF / IPS specific
  nmStep?: 'discovery' | 'probing' | 'fingerprinting' | 'indexing' | 'query';
  nmScannerActive?: boolean;
  nmTargets?: { ip: string, port: number, status: 'scanned' | 'identified' | 'idle', app?: string }[];
  nmQuery?: string;
  wafStep?: 'request' | 'normalization' | 'matching' | 'block' | 'pass';
  wafRuleMatch?: string;
  ipsStep?: 'capture' | 'dpi' | 'alert' | 'drop' | 'allow';
  // Control Flow Flattening specific
  cfwStep?: 'original' | 'analysis' | 'flatten' | 'dispatch_init' | 'dispatch_loop' | 'obfuscated' | 'comparison';
  cfwOriginalCode?: string[];
  cfwFlatCode?: string[];
  cfwBlocks?: { id: string, label: string, code: string[], state: 'active' | 'inactive' }[];
  cfwDispatch?: { value: number, targetBlock: string };
  cfwComplexity?: { original: number, flattened: number };
  isCorrupted?: boolean;
  highlightRegion?: 'buffer' | 'ebp' | 'ret' | 'chunk1' | 'chunk2_header' | 'chunk2' | 'uaf_slot' | 'int_reg' | 'df_chunk';
}

export const STACK_CODE_SNIPPET = `void vulnerable_function(char *input) {
  char buffer[8];
  // No bounds check!
  strcpy(buffer, input);
}`;

export const HEAP_CODE_SNIPPET = `void heap_vuln(char *input) {
  char *chunk1 = malloc(16);
  char *chunk2 = malloc(16);
  // Overflow chunk1 into chunk2's header
  strcpy(chunk1, input);
  free(chunk2);
}`;

export const UAF_CODE_SNIPPET = `void uaf_vuln() {
  char *ptr1 = malloc(16); // Alloc Obj A
  strcpy(ptr1, "SECRET");
  free(ptr1);              // Free Obj A
  // ptr1 is NOT nullified!
  char *ptr2 = malloc(16); // Alloc Obj B
  strcpy(ptr2, "ATTACK");  // Reuses slot
  printf("%s", ptr1);      // UAF Access
}`;

export const FMT_CODE_SNIPPET = `void fmt_vuln(char *input) {
  // Input: "%x %x %x"
  printf(input); 
  // Missing format argument!
}`;

export const INT_OVERFLOW_CODE_SNIPPET = `void int_vuln(unsigned char len, char *data) {
  // len is 8-bit unsigned (0-255)
  // We allocate len + 20 bytes for header
  unsigned char size = len + 20; 
  
  // If len=240: 240 + 20 = 260
  // 260 wraps to 4 (in 8-bit)
  char *buf = malloc(size); 
  
  // Copies 240 bytes into 4-byte buffer!
  memcpy(buf, data, len);
}`;

export const DOUBLE_FREE_CODE_SNIPPET = `void double_free_vuln() {
  char *ptr = malloc(16);
  
  free(ptr);  // First Free
  free(ptr);  // Second Free (VULNERABLE)
  
  // Allocator thinks same chunk is available twice!
  char *p1 = malloc(16);
  char *p2 = malloc(16);
  
  // p1 and p2 now point to the SAME address
  strcpy(p1, "Hacked"); // Corrupts p2
}`;

export const ROP_CODE_SNIPPET = `// NX is enabled: Stack is not executable
// We must reuse existing code snippets (Gadgets)

void vuln() {
  char buf[64];
  gets(buf); // Stack Overflow
}

// Attack Strategy (ROP Chain):
// 1. pop rdi; ret  (Gadget to load arg)
// 2. "/bin/sh"     (Address of string)
// 3. system        (Address of system function)
`;

export const HEAVENS_GATE_CODE_SNIPPET = `// Heaven's Gate: Switching from 32-bit (WoW64) to 64-bit
// Goal: Bypass user-mode hooks (AV/EDR) that only monitor 32-bit APIs.

void heavens_gate() {
    // Current Mode: 32-bit (CS = 0x23)
    
    __asm {
        // 1. Setup Stack for Far Return
        push 0x33        ; Push 64-bit Code Segment Selector (0x33)
        call next_line   ; Push current EIP
        add [esp], 5     ; Adjust Return Address (manually)
        
        // 2. Enter "The Gate"
        retf             ; Far Return -> Pops CS & IP -> Switches CPU Mode!
    }

    // --- 64-bit Realm (CS = 0x33) ---
    // Executing native 64-bit instructions/syscalls here
    // AV hooks on 32-bit ntdll.dll are invisible here.
    
    // 3. Return to 32-bit
    // retf (with 0x23 on stack)
}`;

export const REFLECTIVE_DLL_CODE_SNIPPET = `// Reflective DLL Injection Strategy
// Unlike LoadLibrary, we manually map the DLL from memory.

void Inject() {
    // 1. Read Raw DLL Bytes into local buffer
    ReadFile(hDll, buffer, ...);
    
    // 2. Allocate memory in target process (RWX)
    remoteAddr = VirtualAllocEx(hProcess, ..., PAGE_EXECUTE_READWRITE);
    
    // 3. Copy Raw DLL to target
    WriteProcessMemory(hProcess, remoteAddr, buffer, ...);
    
    // 4. Calculate offset of "ReflectiveLoader" exported function
    DWORD offset = GetReflectiveLoaderOffset(buffer);
    
    // 5. Create Remote Thread starting at ReflectiveLoader
    CreateRemoteThread(hProcess, ..., remoteAddr + offset, ...);
}
`;

export const PROCESS_HOLLOWING_CODE_SNIPPET = `// Process Hollowing (RunPE)
// Goal: Hide malware inside a legitimate process container (e.g., svchost.exe)

void Hollow() {
    // 1. Create legitimate process in SUSPENDED state
    CreateProcess(..., "svchost.exe", ..., CREATE_SUSPENDED, ...);
    
    // 2. Unmap the legitimate code (Hollow it out)
    NtUnmapViewOfSection(hProcess, baseAddr);
    
    // 3. Allocate memory for malware payload
    VirtualAllocEx(hProcess, baseAddr, payloadSize, ...);
    
    // 4. Write malware headers & sections
    WriteProcessMemory(hProcess, baseAddr, payload, ...);
    
    // 5. Update thread context (EAX/RCX) to point to new EntryPoint
    GetThreadContext(hThread, &ctx);
    ctx.Rcx = newEntryPoint;
    SetThreadContext(hThread, &ctx);
    
    // 6. Wake up the zombie process
    ResumeThread(hThread);
}`;

export const PATH_TRAVERSAL_CODE_SNIPPET = `// Vulnerable file read endpoint
app.get('/download', (req, res) => {
  const base = '/var/www/uploads';
  const filename = req.query.file; // e.g. ../../etc/passwd
  // VULNERABLE: naive join without validation
  const filePath = base + '/' + filename; 
  const content = fs.readFileSync(filePath, 'utf8');
  res.send(content);
});

// Secure approach (recommended)
// const sanitized = path.normalize(filename);
// const resolved = path.resolve(base, sanitized);
// if (!resolved.startsWith(base)) return res.status(403).send('Blocked');
// res.send(fs.readFileSync(resolved,'utf8'));`;

export const FILE_UPLOAD_CODE_SNIPPET = `// Node.js / Express (Insecure File Upload)
import fs from 'fs';
import path from 'path';
import multer from 'multer';

// VULNERABLE: stores files under web root, trusts filename & mimetype
const upload = multer({ dest: '/var/www/uploads' });

app.post('/upload', upload.single('file'), (req, res) => {
  const tmpPath = req.file.path;           // e.g. /var/www/uploads/abc123
  const original = req.file.originalname;  // e.g. shell.php

  // VULNERABILITY 1: Use attacker-controlled filename
  const savePath = path.join('/var/www/uploads', original);

  // VULNERABILITY 2: No extension or content-type check
  fs.renameSync(tmpPath, savePath);

  // VULNERABILITY 3: File is web-accessible -> Remote Code Execution if .php/.jsp
  res.send('Uploaded: ' + original);
});

// Secure approach (recommended)
// - Store outside web root
// - Generate random file names
// - Validate extensions & MIME (content sniffing)
// - Strip dangerous paths
// - Apply size and type allowlist`;

export const THREAD_HIJACKING_CODE_SNIPPET = `// Thread Execution Hijacking
// Goal: Piggyback on an existing thread to execute shellcode.

void Hijack(DWORD targetTid) {
    // 1. Open the target thread
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetTid);
    
    // 2. Suspend the thread (Freeze it)
    SuspendThread(hThread);
    
    // 3. Get current registers (Context)
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(hThread, &ctx);
    
    // 4. Allocate and write shellcode
    void* pShellcode = VirtualAllocEx(hProcess, ..., sizeof(shellcode), ...);
    WriteProcessMemory(hProcess, pShellcode, shellcode, ...);
    
    // 5. Point Instruction Pointer (RIP) to Shellcode
    ctx.Rip = (DWORD64)pShellcode;
    SetThreadContext(hThread, &ctx);
    
    // 6. Resume thread (Executes shellcode)
    ResumeThread(hThread);
}`;

export const WEB_CODE_SNIPPET = `<?php
  // VULNERABLE CODE
  $id = $_GET['id'];
  
  // Direct String Concatenation!
  // If id is "1 OR 1=1", query becomes:
  // SELECT * FROM users WHERE id = 1 OR 1=1
  
  $query = "SELECT * FROM users WHERE id = " . $id;
  
  $result = $conn->query($query);
?>`;

export const SSRF_CODE_SNIPPET = `<?php
  // SERVER-SIDE REQUEST FORGERY (SSRF)
  $url = $_GET['url'];
  
  // VULNERABILITY:
  // No validation of the URL scheme, port, or destination IP.
  // The server acts as a proxy, fetching whatever the user requests.
  
  // Attacker can input: "http://127.0.0.1/admin" or "file:///etc/passwd"
  
  $content = file_get_contents($url);
  
  echo $content;
?>`;

export const CSRF_CODE_SNIPPET = `<?php
// transfer.php on Bank Server
session_start();

// VULNERABILITY: 
// Checks if user is logged in (session), but DOES NOT check
// where the request came from (CSRF Token or Referer).

if ($_POST['amount'] && $_POST['to']) {
    $user = $_SESSION['user'];
    
    // The transaction happens immediately based on cookies!
    transfer_money($user, $_POST['to'], $_POST['amount']);
    
    echo "Transfer Successful!";
}
?>`;

export const LOG4SHELL_CODE_SNIPPET = `import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

public class LoginHandler {
    private static final Logger logger = LogManager.getLogger(LoginHandler.class);

    public void handleLogin(String username) {
        // VULNERABILITY:
        // Log4j (versions < 2.15.0) performs "Lookups" inside strings.
        // If username contains "\${jndi:ldap://...}", Log4j evaluates it.
        
        logger.info("User login attempt: " + username);
    }
}`;

export const NEXTJS_RCE_CODE_SNIPPET = `// app/actions.ts (Server Action)
'use server'
import { unstable_cache } from 'next/cache';

export async function getCachedData(key) {
  // VULNERABILITY: CVE-2025-55182
  // The cache key is derived from user input without sanitization.
  // An attacker can inject a payload that poisons the cache with 
  // malicious serialized objects (e.g., flight data).
  
  return unstable_cache(
    async () => {
        return db.query(key); 
    },
    [key], // <--- Poisoned Key
    { tags: ['user-data'] }
  )();
}`;

export const XXE_CODE_SNIPPET = `// PHP XML Parsing Vulnerability
$xmlContent = file_get_contents('php://input');
$dom = new DOMDocument();

// VULNERABILITY:
// LIBXML_NOENT enables the substitution of entities (including external ones).
// LIBXML_DTDLOAD enables loading of DTDs.
// This allows the parser to read local files if defined in the XML.

$dom->loadXML($xmlContent, LIBXML_NOENT | LIBXML_DTDLOAD);

$creds = simplexml_import_dom($dom);
echo "User: " . $creds->user;
`;

export const XSS_CODE_SNIPPET = `// Node.js / Express Example (Stored XSS)

app.post('/comment', (req, res) => {
    // VULNERABILITY:
    // Storing user input directly into the database without sanitization.
    db.saveComment(req.body.text); 
});

app.get('/comments', (req, res) => {
    const comments = db.getComments();
    let html = "<ul>";
    
    // VULNERABILITY:
    // Outputting raw data to the browser.
    // If a comment contains "<script>...</script>", it will execute.
    comments.forEach(c => {
        html += "<li>" + c.text + "</li>"; 
    });
    
    res.send(html + "</ul>");
});
`;

export const DESERIALIZATION_CODE_SNIPPET = `<?php
class Maintenance {
    public $command;

    // MAGIC METHOD:
    // Automatically called when the object is deserialized.
    function __wakeup() {
        // VULNERABILITY: Executes arbitrary command stored in the object
        system($this->command);
    }
}

// Read payload from cookie (Untrusted Input)
$data = $_COOKIE['session_data'];

// Deserializes string into an Object.
// If payload is 'O:11:"Maintenance":1:{s:7:"command";s:6:"whoami";}'
// It creates a Maintenance object and runs whoami immediately.
unserialize($data); 
?>`;

export const FASTJSON_CODE_SNIPPET = `// Java - Fastjson (JSON parsing)
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;

public class UserController {
    // Vulnerable: Using default Fastjson settings
    // Fastjson's autoType feature allows arbitrary class deserialization
    public void processUser(String jsonStr) {
        // VULNERABILITY: autoType=true enables template injection
        // Attacker can inject: {"@type":"...", "...": ...}
        User user = JSON.parseObject(jsonStr, User.class, 
            Feature.AutoType); // ← DANGEROUS
        System.out.println("User: " + user.name);
    }

    // Gadget Chain Execution
    // When autoType loads arbitrary classes, magic methods are triggered
    // e.g., TemplateImpl, SpringTemplateEngine, FreeMarker
    // These can execute arbitrary code in template expressions
}

public class User {
    public String name;
    public String email;
}`;

export const AES_CODE_SNIPPET = `// === Part 1: Algorithmic Logic (Pseudocode) ===
// Shows the structure of AES-128 Encryption
function AES_Encrypt(State, Key) {
    KeyExpansion(Key, RoundKeys); // Generate 11 keys
    
    AddRoundKey(State, RoundKeys[0]); // Initial Round

    // Main Rounds (1 to 9)
    for (i = 1; i < 10; i++) {
        SubBytes(State);
        ShiftRows(State);
        MixColumns(State);
        AddRoundKey(State, RoundKeys[i]);
    }

    // Final Round (No MixColumns!)
    SubBytes(State);
    ShiftRows(State);
    AddRoundKey(State, RoundKeys[10]);
}

// === Part 2: Implementation (Windows C API) ===
// Standard way to encrypt on Windows (wincrypt.h)
void Windows_AES_Example() {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    
    // 1. Acquire Crypto Context
    CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    
    // 2. Import or Generate AES-128 Key
    // (Usually involves CryptImportKey with a PLAINTEXTKEYBLOB)
    CryptGenKey(hProv, CALG_AES_128, CRYPT_EXPORTABLE, &hKey);
    
    // 3. Encrypt Data (In-place)
    // The OS handles rounds, modes (CBC/ECB), and padding transparently.
    DWORD dataLen = strlen(data);
    CryptEncrypt(hKey, 0, TRUE, 0, (BYTE*)data, &dataLen, bufferSize);
    
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
}`;

export const NETWORK_MAPPING_CODE_SNIPPET = `// Simplified Network Mapping Architecture (Golang Style)
// Part 1: Scanner (Distributed Node)
func ScanRange(subnet string) {
    for ip := range subnet {
        // Step 1: TCP Syn Scan
        if probePort(ip, 80) {
            // Step 2: Banner Grabbing
            banner := grabBanner(ip, 80)
            
            // Step 3: Fingerprinting (Regex matching)
            fingerprint := matchRule(banner, "app:Nginx")
            
            // Step 4: Send to Central API
            ReportResult(ip, 80, fingerprint)
        }
    }
}

// Part 2: FOFA Style Query (DSL)
// Query: app="ThinkPHP" && country="CN"
// Platform parses this into an Elasticsearch query:
// { "query": { "bool": { "must": [ { "match": { "app": "ThinkPHP" } } ... ] } } }`;

export const WAF_CODE_SNIPPET = `// WAF Principle (Lua/OpenResty Style)
function OnRequest(req) {
    // 1. Normalization
    local raw_payload = req.body
    local clean_payload = url_decode(lower(raw_payload))

    // 2. Signature Matching (SQLi Example)
    local sqli_pattern = "['\\"]\\s*OR\\s+['\\"]1['\\"]=['\\"]1"
    if match(clean_payload, sqli_pattern) {
        log_threat("SQL Injection Detected")
        return block_request(403)
    }

    // 3. IP Intelligence / RLimit
    if ip_reputation(req.ip) < threshold {
        return captcha_challenge(req)
    }

    // 4. Pass to Upstream
    proxy_pass(backend_server)
}`;

export const IPS_CODE_SNIPPET = `// IPS Deep Packet Inspection (DPI)
void ProcessPacket(Packet pkt) {
    // Layer 3/4 Check
    if (pkt.proto == TCP && pkt.dport == 80) {
        // Layer 7 DPI
        char* payload = pkt.get_l7_payload();
        
        // 1. Signature Lookups (Fast Pattern Matching)
        if (contains(payload, "/etc/passwd")) {
            // 2. Immediate Prevention
            DropPacket(pkt);
            SendTCPReset(pkt);
            UpdateACL(pkt.src_ip, 3600); // Temporary Ban
            return;
        }
    }
    
    // 3. Forward Packet
    ForwardPacket(pkt);
}`;

export const CFW_CODE_SNIPPET = `// Original Code (Clear Control Flow)
int authenticate(int id, char *password) {
    if (id < 1000) {
        log_event("Low privilege attempt");
        return 0;
    }
    
    if (check_password(password)) {
        grant_access();
        return 1;
    }
    
    return 0;
}

/* AFTER Control Flow Flattening (Obfuscated)
   The code is transformed into a state machine:
   - All basic blocks become numbered states
   - All jumps become state transitions
   - Original intent becomes unrecognizable
*/
int authenticate_flat(int id, char *password) {
    int state = 0;
    while(1) {
        switch(state) {
            case 0:  // Block 0: Entry
                goto case_1;
            case 1:  // Block 1: Check ID
                if (id < 1000) state = 2; else state = 3;
                break;
            case 2:  // Block 2: Low privilege
                log_event("Low privilege attempt");
                state = 4;
                break;
            case 3:  // Block 3: Check password
                if (check_password(password)) state = 5; else state = 6;
                break;
            case 4:  // Block 4: Return 0
                return 0;
            case 5:  // Block 5: Grant access
                grant_access();
                state = 7;
                break;
            case 6:  // Block 6: Password fail
                state = 4;
                break;
            case 7:  // Block 7: Return 1
                return 1;
        }
    }
}`;

export const SQLI_CHEAT_SHEET = {
    auth_bypass: [
        "' OR '1'='1",
        "' OR 1=1 --",
        "admin' --",
        "admin' #"
    ],
    fingerprinting: [
        { db: "MySQL", check: "SELECT version()", comment: "# or -- " },
        { db: "PostgreSQL", check: "SELECT version()", comment: "--" },
        { db: "MSSQL", check: "SELECT @@version", comment: "--" },
        { db: "Oracle", check: "SELECT banner FROM v$version", comment: "--" },
    ],
    union_attacks: [
        "' UNION SELECT 1,2,3 --",
        "' UNION SELECT null, username, password FROM users --"
    ]
};
