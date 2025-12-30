import React from 'react';
import { AnimationStep } from '../types';
import { Play, Pause, Activity, Cpu, ArrowRight, CornerDownRight } from 'lucide-react';

interface ThreadHijackingVisualizerProps {
  step: AnimationStep;
}

export const ThreadHijackingVisualizer: React.FC<ThreadHijackingVisualizerProps> = ({ step }) => {
  
  const state = step.thState || 'running';
  const thread = step.thThread || { id: 1024, status: 'Running', rip: '0x7FF...Legit', codeBlock: 'Legit' };

  return (
    <div className="flex flex-col gap-8 w-full max-w-4xl mx-auto p-4">
        
        {/* Thread Pipeline Visualization */}
        <div className="relative bg-slate-900 border border-slate-700 rounded-xl p-8 overflow-hidden min-h-[250px] flex flex-col justify-center">
            
            {/* Background Grid */}
            <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/grid-me.png')] opacity-10"></div>

            <div className="flex items-center justify-between relative z-10 px-8">
                
                {/* Code Blocks */}
                <div className="flex flex-col gap-6 w-1/3">
                    <div className={`p-4 rounded border-l-4 transition-all duration-300 ${thread.codeBlock === 'Legit' ? 'bg-blue-900/20 border-blue-500 shadow-[0_0_15px_rgba(59,130,246,0.3)]' : 'bg-slate-800 border-slate-600 opacity-50'}`}>
                        <div className="text-xs font-bold text-slate-400 uppercase mb-1">Text Segment</div>
                        <div className="text-sm font-mono text-blue-300">Normal Application Code</div>
                        <div className="text-[10px] text-slate-500 mt-1">addr: 0x401000</div>
                    </div>

                    <div className={`p-4 rounded border-l-4 transition-all duration-300 ${thread.codeBlock === 'Shellcode' ? 'bg-red-900/20 border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)]' : 'bg-slate-800 border-slate-600 opacity-30'}`}>
                        <div className="text-xs font-bold text-slate-400 uppercase mb-1">Heap / Stack</div>
                        <div className="text-sm font-mono text-red-300">Injected Shellcode</div>
                        <div className="text-[10px] text-slate-500 mt-1">addr: 0x900000</div>
                    </div>
                </div>

                {/* The Pointer Arrow */}
                <div className="flex flex-col items-center justify-center w-1/3 h-full relative">
                     <div className={`transition-all duration-700 absolute left-0 
                         ${thread.codeBlock === 'Legit' ? 'top-8' : 'top-32'}
                     `}>
                         <ArrowRight size={40} className={`transition-colors duration-300 ${thread.codeBlock === 'Legit' ? 'text-blue-500' : 'text-red-500'}`} />
                     </div>
                </div>

                {/* CPU Thread Context */}
                <div className="w-1/3 flex flex-col items-center gap-4">
                    <div className={`w-32 h-32 rounded-full border-4 flex flex-col items-center justify-center shadow-2xl transition-all duration-500 relative
                        ${thread.status === 'Running' ? 'border-green-500 bg-green-900/10' : 'border-yellow-500 bg-yellow-900/10'}
                    `}>
                        {thread.status === 'Running' ? (
                            <Activity size={40} className="text-green-400 animate-pulse" />
                        ) : (
                            <Pause size={40} className="text-yellow-400" />
                        )}
                        <span className="text-xs font-bold text-slate-300 mt-2">TID: {thread.id}</span>
                        
                        {/* Status Badge */}
                        <div className={`absolute -bottom-3 px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider
                            ${thread.status === 'Running' ? 'bg-green-600 text-white' : 'bg-yellow-600 text-black'}
                        `}>
                            {thread.status}
                        </div>
                    </div>

                    {/* Registers */}
                    <div className="bg-[#1e1e1e] w-full p-3 rounded border border-gray-600 flex flex-col gap-1">
                        <div className="flex items-center gap-2 text-xs text-gray-500 uppercase font-bold border-b border-gray-700 pb-1 mb-1">
                            <Cpu size={12} /> Context
                        </div>
                        <div className="flex justify-between font-mono text-xs">
                            <span className="text-slate-400">RIP</span>
                            <span className={`transition-colors duration-300 ${thread.codeBlock === 'Shellcode' ? 'text-red-400 font-bold' : 'text-blue-300'}`}>
                                {thread.rip}
                            </span>
                        </div>
                    </div>
                </div>

            </div>
        </div>

        {/* Steps Legend */}
        <div className="grid grid-cols-5 gap-2">
            {['open', 'suspend', 'inject', 'context', 'resume'].map((s, i) => (
                <div key={s} className={`p-2 rounded text-center text-[10px] font-bold uppercase transition-all duration-300 border
                    ${state === s ? 'bg-blue-600 border-blue-400 text-white scale-105' : 'bg-slate-800 border-slate-700 text-slate-500'}
                `}>
                    {i + 1}. {s}
                </div>
            ))}
        </div>

    </div>
  );
};
