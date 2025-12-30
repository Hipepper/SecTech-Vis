
import React from 'react';
import { AnimationStep } from '../types';
import { Laptop, Server, FileText, ArrowRight, ArrowLeft, Database, Settings } from 'lucide-react';

interface XxeVisualizerProps {
  step: AnimationStep;
}

export const XxeVisualizer: React.FC<XxeVisualizerProps> = ({ step }) => {
  const currentState = step.xxeStep || 'input';
  
  // Animation triggers
  const showParse = ['parse', 'resolve', 'access', 'response'].includes(currentState);
  const showResolve = ['resolve', 'access', 'response'].includes(currentState);
  const showAccess = ['access', 'response'].includes(currentState);
  const showResponse = currentState === 'response';

  return (
    <div className="flex flex-col gap-8 w-full max-w-5xl mx-auto p-4">
        
        {/* TOP: Attacker & Payload */}
        <div className="flex gap-6 items-center justify-center">
            <div className="flex flex-col items-center gap-2">
                <div className="p-4 bg-slate-900 border border-slate-700 rounded-xl flex flex-col items-center shadow-lg">
                    <Laptop size={32} className="text-red-400" />
                    <span className="text-xs font-bold text-slate-400 mt-2">Attacker</span>
                </div>
            </div>

            {/* Attack Vector Payload */}
            <div className="flex-1 bg-[#1e1e1e] p-4 rounded-xl border border-slate-600 font-mono text-xs relative overflow-hidden">
                <div className="text-[10px] text-slate-500 uppercase font-bold mb-2">Malicious XML Payload</div>
                <div className="text-blue-300">&lt;?xml version="1.0"?&gt;</div>
                <div className="text-yellow-300">&lt;!DOCTYPE foo [</div>
                <div className="pl-4 text-green-300">
                    &lt;!ELEMENT foo ANY&gt;<br/>
                    &lt;!ENTITY <span className="text-red-400 font-bold">xxe</span> SYSTEM "<span className="text-red-400 font-bold">file:///etc/passwd</span>"&gt;
                </div>
                <div className="text-yellow-300">]&gt;</div>
                <div className="text-slate-300">
                    &lt;foo&gt;<span className="text-red-400 font-bold">&amp;xxe;</span>&lt;/foo&gt;
                </div>

                {/* Arrow to Server */}
                <div className={`absolute right-4 top-1/2 -translate-y-1/2 transition-all duration-500 ${currentState === 'input' ? 'translate-x-0 opacity-100' : 'translate-x-10 opacity-0'}`}>
                    <ArrowRight size={24} className="text-red-500 animate-pulse" />
                </div>
            </div>
        </div>

        {/* MIDDLE: Server Processing */}
        <div className={`
            bg-slate-900 border-2 rounded-xl p-6 relative transition-all duration-500 flex flex-col gap-6
            ${showParse ? 'border-purple-500 bg-purple-900/10' : 'border-slate-700'}
        `}>
            <div className="absolute -top-3 left-6 bg-[#0f172a] px-2 text-xs font-bold text-slate-400 uppercase flex items-center gap-2">
                <Server size={14} className="text-purple-400" />
                Vulnerable XML Parser (DOMDocument)
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
                
                {/* 1. Parser Logic */}
                <div className="flex flex-col gap-2">
                    <div className="flex items-center gap-2 text-xs text-slate-300 bg-slate-800 p-2 rounded border border-slate-600">
                        <Settings size={14} className={showParse ? 'text-green-400 animate-spin-slow' : 'text-slate-500'} />
                        <span>Config: <span className="font-mono text-red-300">LIBXML_NOENT (Subst Entities)</span></span>
                    </div>
                    
                    <div className="bg-black/40 p-4 rounded border border-slate-600 min-h-[100px] flex flex-col justify-center">
                        {!showParse && <span className="text-slate-600 text-xs text-center">Waiting for input...</span>}
                        {showParse && (
                            <div className="flex flex-col gap-2 text-xs font-mono">
                                <div className="text-slate-400">Parsing DTD...</div>
                                <div className={`transition-all duration-500 ${showResolve ? 'opacity-100' : 'opacity-0'}`}>
                                    <span className="text-purple-300">Found ENTITY 'xxe'</span><br/>
                                    <span className="text-yellow-300">Type: SYSTEM (External)</span><br/>
                                    <span className="text-red-400">URI: file:///etc/passwd</span>
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                {/* 2. File System Access */}
                <div className={`
                    border-2 border-dashed rounded-xl p-4 flex flex-col items-center justify-center relative transition-all duration-500
                    ${showAccess ? 'border-red-500 bg-red-900/20' : 'border-slate-600 bg-slate-800/30 opacity-50'}
                `}>
                    <div className="absolute -top-3 bg-[#0f172a] px-2 text-[10px] font-bold text-slate-500 uppercase">Local File System</div>
                    <FileText size={40} className={showAccess ? 'text-slate-200' : 'text-slate-600'} />
                    <span className="text-xs font-mono text-slate-400 mt-2">/etc/passwd</span>
                    
                    {showAccess && (
                        <div className="absolute inset-0 flex items-center justify-center">
                            <div className="bg-red-600 text-white text-[10px] font-bold px-2 py-1 rounded shadow animate-bounce">
                                READ ACCESS
                            </div>
                        </div>
                    )}
                </div>

            </div>
        </div>

        {/* BOTTOM: Response */}
        <div className={`
            bg-black border border-green-500/30 rounded-xl p-4 transition-all duration-500 relative min-h-[80px] flex items-center
            ${showResponse ? 'opacity-100 translate-y-0' : 'opacity-50 translate-y-4'}
        `}>
            <div className="absolute -top-3 left-6 bg-[#0f172a] px-2 text-[10px] font-bold text-green-500 uppercase">Server Response</div>
            {showResponse ? (
                <div className="text-xs font-mono text-green-300 w-full break-all">
                    root:x:0:0:root:/root:/bin/bash<br/>
                    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin<br/>
                    bin:x:2:2:bin:/bin:/usr/sbin/nologin...
                </div>
            ) : (
                <div className="text-xs font-mono text-slate-600 w-full text-center">Waiting for server response...</div>
            )}
            
            {showResponse && (
                <div className="absolute right-4 top-1/2 -translate-y-1/2">
                    <ArrowLeft size={24} className="text-green-500 animate-pulse" />
                </div>
            )}
        </div>

    </div>
  );
};
