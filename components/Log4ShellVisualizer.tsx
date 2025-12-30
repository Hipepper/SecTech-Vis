
import React from 'react';
import { AnimationStep } from '../types';
import { Laptop, Server, Globe, ArrowDown, ArrowUp, Terminal, Code, Box, CloudLightning } from 'lucide-react';

interface Log4ShellVisualizerProps {
  step: AnimationStep;
}

export const Log4ShellVisualizer: React.FC<Log4ShellVisualizerProps> = ({ step }) => {
  const currentState = step.l4sStep || 'input';
  
  // States for animation control
  const showLdapReq = ['ldap_req', 'ldap_res', 'class_download', 'rce'].includes(currentState);
  const showLdapRes = ['ldap_res', 'class_download', 'rce'].includes(currentState);
  const showDownload = ['class_download', 'rce'].includes(currentState);
  const showRce = currentState === 'rce';

  return (
    <div className="flex flex-col gap-6 w-full max-w-4xl mx-auto p-4">
        
        {/* 1. ATTACKER (CLIENT) */}
        <div className="relative flex flex-col gap-2">
            <div className="flex items-center gap-2 text-red-400 font-bold uppercase tracking-wider text-sm">
                <Laptop size={18} /> Attacker (Client)
            </div>
            <div className="w-full bg-slate-900 border border-slate-700 rounded-xl p-6 shadow-lg flex items-center justify-between gap-4">
                <div className="flex-1">
                    <div className="text-[10px] text-slate-500 uppercase mb-1">Malicious HTTP Header</div>
                    <div className="bg-black p-3 rounded text-sm font-mono text-green-400 border border-slate-700 break-all">
                        User-Agent: {step.l4sPayload}
                    </div>
                </div>
                <div className="hidden sm:block">
                    <CloudLightning className="text-red-500" size={32} />
                </div>
            </div>
        </div>

        {/* CONNECTION: HTTP Request */}
        <div className="flex justify-center -my-2 relative z-10">
             <div className={`transition-all duration-500 flex flex-col items-center
                 ${currentState === 'input' || currentState === 'logging' ? 'opacity-100' : 'opacity-30'}
             `}>
                 <div className="h-8 w-0.5 bg-blue-500"></div>
                 <div className="bg-blue-600 text-white text-[10px] px-2 py-1 rounded-full shadow-lg font-bold">
                     1. HTTP Request
                 </div>
                 <ArrowDown size={24} className="text-blue-500 -mt-1" />
             </div>
        </div>

        {/* 2. VULNERABLE SERVER */}
        <div className="relative flex flex-col gap-2">
            <div className="flex items-center gap-2 text-blue-400 font-bold uppercase tracking-wider text-sm">
                <Box size={18} /> Vulnerable Java App (Log4j)
            </div>
            <div className={`w-full bg-slate-900 border-2 rounded-xl p-6 shadow-lg transition-colors duration-500 flex flex-col gap-4
                ${showRce ? 'border-red-500 bg-red-900/10' : 'border-slate-700'}
            `}>
                <div className="absolute top-0 right-6 bg-orange-600 px-3 py-1 rounded-b text-xs text-white font-bold shadow">
                    Log4j 2.14.1
                </div>

                {/* Log Processing */}
                <div className="flex flex-col gap-2">
                    <div className="text-xs text-slate-500 font-mono">// Application Log Processing</div>
                    <div className="bg-[#1e1e1e] p-4 rounded border border-slate-600 font-mono text-sm text-slate-300">
                        <span className="text-slate-500">{`[INFO] Request received.`}</span><br/>
                        <span>{`[INFO] User-Agent: `}</span>
                        <span className="text-yellow-400 font-bold">{step.l4sPayload}</span>
                    </div>
                </div>

                {/* Internal State */}
                {currentState === 'lookup' && (
                    <div className="bg-yellow-900/20 border border-yellow-500/30 p-2 rounded text-yellow-200 text-xs text-center animate-pulse">
                        ⚠ JNDI Lookup Detected: attempting to resolve ldap://...
                    </div>
                )}

                {/* RCE Visual */}
                {showRce && (
                    <div className="mt-2 bg-red-600 text-white p-4 rounded-lg shadow-xl animate-bounce flex items-center justify-center gap-3">
                        <Terminal size={24} />
                        <span className="font-bold text-lg">REMOTE SHELL OPENED</span>
                    </div>
                )}
            </div>
        </div>

        {/* CONNECTION: JNDI / LDAP */}
        <div className="flex justify-center -my-2 relative z-10 gap-16">
             {/* Down: Query */}
             <div className={`transition-all duration-500 flex flex-col items-center
                 ${showLdapReq ? 'opacity-100 translate-y-0' : 'opacity-0 -translate-y-4'}
             `}>
                 <div className="h-8 w-0.5 bg-red-500"></div>
                 <ArrowDown size={24} className="text-red-500 -mt-1" />
                 <span className="text-[10px] text-red-300 font-bold bg-slate-800 px-2 rounded mt-1 border border-red-500/30">
                     2. LDAP Query
                 </span>
             </div>

             {/* Up: Response */}
             <div className={`transition-all duration-500 flex flex-col-reverse items-center
                 ${showLdapRes ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}
             `}>
                 <div className="h-8 w-0.5 bg-purple-500"></div>
                 <ArrowUp size={24} className="text-purple-500 -mb-1" />
                 <span className="text-[10px] text-purple-300 font-bold bg-slate-800 px-2 rounded mb-1 border border-purple-500/30">
                     {showDownload ? "4. Download Class" : "3. LDAP Ref"}
                 </span>
             </div>
        </div>

        {/* 3. ATTACKER INFRASTRUCTURE */}
        <div className="relative flex flex-col gap-2">
            <div className="flex items-center gap-2 text-purple-400 font-bold uppercase tracking-wider text-sm">
                <Globe size={18} /> Attacker Infrastructure
            </div>
            <div className="w-full bg-slate-900 border border-slate-700 rounded-xl p-6 shadow-lg grid grid-cols-2 gap-6">
                
                {/* LDAP Server */}
                <div className={`p-4 rounded-lg border flex flex-col items-center gap-2 transition-all duration-300
                    ${showLdapReq ? 'bg-slate-800 border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.2)]' : 'bg-slate-800/50 border-slate-700 opacity-50'}
                `}>
                    <Globe size={32} className={showLdapReq ? "text-red-400" : "text-slate-600"} />
                    <div className="text-center">
                        <div className="text-xs font-bold text-slate-300">LDAP Server</div>
                        <div className="text-[10px] font-mono text-slate-500">:1389</div>
                    </div>
                    {showLdapReq && <div className="text-[10px] text-red-300 animate-pulse">Query Received</div>}
                </div>

                {/* HTTP Server */}
                <div className={`p-4 rounded-lg border flex flex-col items-center gap-2 transition-all duration-300
                    ${showDownload ? 'bg-slate-800 border-purple-500/50 shadow-[0_0_15px_rgba(168,85,247,0.2)]' : 'bg-slate-800/50 border-slate-700 opacity-50'}
                `}>
                    <Server size={32} className={showDownload ? "text-purple-400" : "text-slate-600"} />
                    <div className="text-center">
                        <div className="text-xs font-bold text-slate-300">HTTP Server</div>
                        <div className="text-[10px] font-mono text-slate-500">:8000</div>
                    </div>
                    {showDownload && <div className="text-[10px] text-purple-300 animate-pulse">Serving Exploit.class</div>}
                </div>

            </div>
        </div>

        {/* Technical Explainer Footer */}
        <div className="bg-slate-900 border border-slate-700 rounded-xl p-4 flex gap-4 items-start mt-2">
            <div className="bg-slate-800 p-2 rounded-full mt-1">
                <Code className="text-blue-400" size={20} />
            </div>
            <div>
                <h3 className="text-sm font-bold text-slate-200 mb-1">Technical Step Analysis</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                    {currentState === 'input' && "The attacker crafts a specific JNDI string payload. This payload uses the LDAP protocol wrapper."}
                    {currentState === 'logging' && "The vulnerable Java application logs the string (e.g. User-Agent header) using a vulnerable version of Log4j."}
                    {currentState === 'lookup' && "Log4j's lookup feature interprets '${jndi:...}' and attempts to resolve the object, unaware it triggers a network call."}
                    {currentState === 'ldap_req' && "JNDI initiates a request to the attacker's LDAP server to find the object named in the path."}
                    {currentState === 'ldap_res' && "The LDAP server returns a 'Reference' object containing the location (URL) of a remote Java class file."}
                    {currentState === 'class_download' && "The victim JVM fetches the remote '.class' file from the attacker's HTTP server to instantiate the object."}
                    {currentState === 'rce' && "Upon loading the class, the static initializer block executes arbitrary code (the payload), compromising the server."}
                </p>
            </div>
        </div>

    </div>
  );
};
