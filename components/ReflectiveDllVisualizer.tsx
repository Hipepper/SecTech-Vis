import React from 'react';
import { AnimationStep } from '../types';
import { ArrowRight, Box, Cpu, FileCog, Search, Zap } from 'lucide-react';

interface ReflectiveDllVisualizerProps {
  step: AnimationStep;
}

export const ReflectiveDllVisualizer: React.FC<ReflectiveDllVisualizerProps> = ({ step }) => {
  
  const state = step.rdllState || 'idle';
  const injector = step.rdllInjector || { action: 'Idle', active: false };
  const target = step.rdllTarget || { memory: [], threadStatus: 'Waiting' };

  return (
    <div className="flex flex-col gap-6 w-full max-w-5xl mx-auto p-4">
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            
            {/* INJECTOR PROCESS */}
            <div className={`relative p-6 rounded-xl border-2 transition-all duration-500 
                ${injector.active ? 'border-blue-500 bg-blue-900/10' : 'border-slate-700 bg-slate-800/50'}`}>
                
                <div className="absolute -top-3 left-4 bg-slate-900 px-2 text-xs font-bold text-slate-400 uppercase flex items-center gap-2">
                    <Box size={14} className="text-blue-400" />
                    Injector Process (Attacker)
                </div>

                <div className="flex flex-col gap-4 mt-2">
                    <div className="flex items-center gap-3">
                         <div className="p-2 bg-slate-800 rounded border border-slate-600">
                             <FileCog className="text-yellow-400" size={24} />
                         </div>
                         <div className="flex flex-col">
                             <span className="text-sm font-bold text-slate-200">Malicious DLL</span>
                             <span className="text-xs text-slate-500 font-mono">Raw Bytes on Disk/Mem</span>
                         </div>
                    </div>

                    <div className="h-px bg-slate-700 w-full"></div>

                    <div className="flex flex-col gap-1">
                        <span className="text-[10px] text-slate-500 uppercase font-bold">Current Action</span>
                        <div className={`text-sm font-mono transition-colors duration-300 ${injector.active ? 'text-blue-300' : 'text-slate-400'}`}>
                            {injector.action}
                        </div>
                    </div>
                </div>

                {/* Arrow to Target */}
                {state === 'write' && (
                    <div className="absolute -right-4 top-1/2 -translate-y-1/2 z-20">
                         <div className="bg-blue-600 p-2 rounded-full shadow-[0_0_15px_rgba(37,99,235,0.5)] animate-pulse">
                             <ArrowRight className="text-white" size={20} />
                         </div>
                    </div>
                )}
            </div>

            {/* TARGET PROCESS */}
            <div className={`relative p-6 rounded-xl border-2 transition-all duration-500 
                ${state !== 'idle' && state !== 'alloc' && state !== 'write' ? 'border-red-500 bg-red-900/10' : 'border-slate-700 bg-slate-800/50'}`}>
                
                <div className="absolute -top-3 left-4 bg-slate-900 px-2 text-xs font-bold text-slate-400 uppercase flex items-center gap-2">
                    <Box size={14} className={state !== 'idle' && state !== 'alloc' && state !== 'write' ? 'text-red-400' : 'text-slate-400'} />
                    Target Process (Victim)
                </div>

                {/* Memory Map Representation */}
                <div className="flex flex-col gap-2 mt-2">
                    <div className="flex justify-between text-[10px] text-slate-500 uppercase font-bold mb-1">
                        <span>Heap Memory</span>
                        <span>Execution Status</span>
                    </div>

                    <div className="bg-[#151515] p-2 rounded border border-slate-700 min-h-[120px] flex flex-col gap-1">
                         {target.memory.length === 0 && (
                             <div className="text-slate-600 text-xs text-center py-8 italic">Memory Normal</div>
                         )}
                         {target.memory.map((block, i) => (
                             <div key={i} className={`
                                 flex items-center justify-between p-2 rounded text-xs font-mono border transition-all duration-500
                                 ${block.type === 'free' ? 'bg-slate-800 border-slate-700 text-slate-500' : ''}
                                 ${block.type === 'dll_raw' ? 'bg-blue-900/20 border-blue-500/50 text-blue-300' : ''}
                                 ${block.type === 'dll_mapped' ? 'bg-red-900/20 border-red-500/50 text-red-300' : ''}
                                 ${block.highlight ? 'ring-2 ring-yellow-400 scale-[1.02]' : ''}
                             `}>
                                 <span>{block.label}</span>
                                 <span className="opacity-50 text-[10px]">{block.type.toUpperCase().replace('_', ' ')}</span>
                                 
                                 {block.active && (
                                     <div className="w-2 h-2 rounded-full bg-yellow-400 animate-pulse"></div>
                                 )}
                             </div>
                         ))}
                    </div>

                    <div className="mt-2 flex items-center justify-between bg-black/20 p-2 rounded border border-slate-700">
                        <div className="flex items-center gap-2">
                            <Cpu size={14} className="text-slate-400" />
                            <span className="text-xs text-slate-300">Thread Context:</span>
                        </div>
                        <span className={`text-xs font-bold ${target.threadStatus === 'Running Malware' ? 'text-red-400 animate-pulse' : 'text-slate-400'}`}>
                            {target.threadStatus}
                        </span>
                    </div>
                </div>
            </div>

        </div>

        {/* REFLECTIVE LOADER DETAIL (The "Magic" Box) */}
        <div className={`transition-all duration-700 overflow-hidden rounded-xl border border-slate-700 bg-[#1e1e1e]
             ${state === 'boot' || state === 'reloc' || state === 'imports' || state === 'exec' ? 'opacity-100 max-h-[300px] p-6' : 'opacity-0 max-h-0 p-0'}
        `}>
             <div className="flex items-center gap-2 mb-4 border-b border-gray-700 pb-2">
                 <Search className="text-purple-400" size={18} />
                 <h3 className="font-bold text-slate-200">Inside the "Reflective Loader"</h3>
             </div>

             <div className="grid grid-cols-3 gap-4">
                 <div className={`flex flex-col items-center gap-2 p-3 rounded border ${state === 'boot' ? 'bg-purple-900/20 border-purple-500 text-purple-200' : 'bg-slate-800 border-slate-700 text-slate-500'}`}>
                     <span className="text-xs font-bold uppercase">1. Bootstrap</span>
                     <span className="text-[10px] text-center">Find PEB & Kernel32 Address</span>
                 </div>
                 <div className={`flex flex-col items-center gap-2 p-3 rounded border ${state === 'imports' ? 'bg-purple-900/20 border-purple-500 text-purple-200' : 'bg-slate-800 border-slate-700 text-slate-500'}`}>
                     <span className="text-xs font-bold uppercase">2. Imports</span>
                     <span className="text-[10px] text-center">LoadLibrary & GetProcAddress</span>
                 </div>
                 <div className={`flex flex-col items-center gap-2 p-3 rounded border ${state === 'reloc' ? 'bg-purple-900/20 border-purple-500 text-purple-200' : 'bg-slate-800 border-slate-700 text-slate-500'}`}>
                     <span className="text-xs font-bold uppercase">3. Relocations</span>
                     <span className="text-[10px] text-center">Fix Hardcoded Addresses (The Key Step)</span>
                 </div>
             </div>

             <div className="mt-4 flex justify-center">
                 {state === 'exec' && (
                     <div className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg shadow-lg animate-bounce">
                         <Zap size={16} fill="currentColor" />
                         <span className="font-bold text-sm">DllMain() Executed!</span>
                     </div>
                 )}
             </div>
        </div>

    </div>
  );
};
