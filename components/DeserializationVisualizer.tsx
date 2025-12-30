
import React from 'react';
import { AnimationStep } from '../types';
import { Laptop, Server, Box, ArrowRight, Settings, Terminal, Zap, Code } from 'lucide-react';

interface DeserializationVisualizerProps {
  step: AnimationStep;
}

export const DeserializationVisualizer: React.FC<DeserializationVisualizerProps> = ({ step }) => {
  const currentState = step.deserStep || 'craft';
  
  // Animation triggers
  const showCraft = ['craft', 'send', 'parse', 'magic_method', 'rce'].includes(currentState);
  const showSend = ['send', 'parse', 'magic_method', 'rce'].includes(currentState);
  const showParse = ['parse', 'magic_method', 'rce'].includes(currentState);
  const showMagic = ['magic_method', 'rce'].includes(currentState);
  const showRce = currentState === 'rce';

  return (
    <div className="flex flex-col gap-8 w-full max-w-5xl mx-auto p-4">
        
        {/* ROW 1: Attacker & Payload */}
        <div className="flex gap-8 items-stretch justify-center">
            
            {/* Attacker */}
            <div className="flex flex-col gap-2 w-1/3">
                <div className="flex items-center gap-2 text-red-400 font-bold uppercase tracking-wider text-sm">
                    <Laptop size={18} /> Attacker
                </div>
                <div className={`flex-1 bg-slate-900 border border-slate-700 rounded-xl p-4 shadow-lg flex flex-col gap-2 transition-all duration-500
                    ${currentState === 'craft' ? 'border-red-500 ring-1 ring-red-500/50' : ''}
                `}>
                    <div className="text-[10px] text-slate-500 uppercase font-bold">Crafted Payload (PHP Serialize)</div>
                    <div className="bg-black p-3 rounded font-mono text-xs text-yellow-400 break-all border border-slate-600 leading-relaxed">
                        O:11:"<span className="text-red-400 font-bold">Maintenance</span>":1:&#123;<br/>
                        &nbsp;&nbsp;s:7:"<span className="text-blue-400">command</span>";<br/>
                        &nbsp;&nbsp;s:6:"<span className="text-red-400 font-bold">whoami</span>";<br/>
                        &#125;
                    </div>
                    {currentState === 'craft' && (
                        <div className="text-[10px] text-slate-400 italic mt-2">
                            Encoding a malicious object state into a string format.
                        </div>
                    )}
                </div>
            </div>

            {/* Arrow */}
            <div className="flex items-center justify-center w-1/6 relative">
                <div className={`transition-all duration-700 ${showSend ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4'}`}>
                    <ArrowRight size={32} className="text-red-500" />
                </div>
            </div>

            {/* Server */}
            <div className="flex flex-col gap-2 w-1/3">
                <div className="flex items-center gap-2 text-blue-400 font-bold uppercase tracking-wider text-sm">
                    <Server size={18} /> Vulnerable Server
                </div>
                <div className={`flex-1 bg-slate-900 border border-slate-700 rounded-xl p-4 shadow-lg flex flex-col items-center justify-center relative overflow-hidden transition-all duration-500
                    ${showParse ? 'bg-blue-900/10 border-blue-500' : ''}
                `}>
                    {/* Deserialize Box */}
                    <div className="bg-[#1e1e1e] p-2 rounded border border-slate-600 mb-4 w-full text-center">
                        <div className="text-[10px] text-purple-400 font-mono mb-1">Function Call</div>
                        <div className="text-sm font-mono text-slate-200">unserialize($payload)</div>
                    </div>

                    {/* Object Construction */}
                    {showParse && (
                        <div className="animate-in zoom-in duration-500 bg-slate-800 p-3 rounded border border-slate-600 w-full flex items-center gap-3">
                            <Box className="text-green-400" size={24} />
                            <div className="flex flex-col">
                                <span className="text-xs font-bold text-slate-200">Object Created</span>
                                <span className="text-[10px] font-mono text-slate-400">Class: Maintenance</span>
                                <span className="text-[10px] font-mono text-red-300">prop: command="whoami"</span>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>

        {/* ROW 2: Execution Logic */}
        <div className={`transition-all duration-700 ${showMagic ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
            <div className="relative bg-slate-900 border border-slate-700 rounded-xl p-6 flex flex-col gap-4">
                <div className="absolute top-0 left-0 bg-slate-800 px-3 py-1 rounded-br-xl border-r border-b border-slate-700 text-xs font-bold text-slate-400 uppercase flex items-center gap-2">
                    <Code size={12} /> Class Definition & Execution
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mt-4">
                    
                    {/* Magic Method Logic */}
                    <div className="flex flex-col gap-2">
                        <div className="flex items-center gap-2 text-yellow-400 font-bold text-xs uppercase">
                            <Settings size={14} className={showMagic ? 'animate-spin-slow' : ''} /> 
                            Magic Method Triggered
                        </div>
                        <div className="bg-[#1e1e1e] p-4 rounded border border-slate-600 font-mono text-xs text-slate-300 relative">
                            <span className="text-purple-400">class</span> Maintenance &#123;<br/>
                            &nbsp;&nbsp;<span className="text-purple-400">function</span> <span className="text-yellow-300">__wakeup()</span> &#123;<br/>
                            &nbsp;&nbsp;&nbsp;&nbsp;<span className="text-slate-500">// Auto-runs on unserialize</span><br/>
                            &nbsp;&nbsp;&nbsp;&nbsp;<span className={`transition-colors duration-300 ${showRce ? 'text-red-400 font-bold' : ''}`}>system($this-&gt;command);</span><br/>
                            &nbsp;&nbsp;&#125;<br/>
                            &#125;
                            
                            {showMagic && (
                                <div className="absolute right-4 top-1/2 -translate-y-1/2">
                                    <div className="bg-yellow-600 text-black text-[10px] font-bold px-2 py-1 rounded shadow animate-pulse">
                                        CALLED!
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* RCE Result */}
                    <div className="flex flex-col gap-2">
                        <div className="flex items-center gap-2 text-red-400 font-bold text-xs uppercase">
                            <Zap size={14} /> Execution Result
                        </div>
                        <div className="bg-black p-4 rounded border border-slate-600 h-full font-mono text-xs flex flex-col">
                            <div className="flex items-center gap-2 text-slate-500 border-b border-slate-800 pb-1 mb-2">
                                <Terminal size={12} /> System Shell
                            </div>
                            {showRce ? (
                                <div className="animate-in fade-in slide-in-from-bottom-2">
                                    <span className="text-green-400">$ whoami</span><br/>
                                    <span className="text-white">root</span><br/>
                                    <span className="text-green-400">$ _</span>
                                </div>
                            ) : (
                                <span className="text-slate-600 italic">Waiting for command...</span>
                            )}
                        </div>
                    </div>

                </div>
            </div>
        </div>

    </div>
  );
};
