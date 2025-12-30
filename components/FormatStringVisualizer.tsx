import React from 'react';
import { AnimationStep } from '../types';
import { Terminal, ArrowUp } from 'lucide-react';

interface FormatStringVisualizerProps {
  step: AnimationStep;
}

export const FormatStringVisualizer: React.FC<FormatStringVisualizerProps> = ({ step }) => {
  
  const stackItems = step.fmtStackValues || ["..."];
  const readIndex = step.fmtReadIndex !== undefined ? step.fmtReadIndex : -1;

  return (
    <div className="flex flex-col lg:flex-row gap-6 w-full max-w-4xl mx-auto items-start">
        
        {/* Stack View */}
        <div className="flex-1 w-full bg-[#1e1e1e] border border-gray-600 rounded-sm shadow-xl p-4">
             <div className="text-xs font-bold text-gray-400 mb-4 uppercase tracking-wider border-b border-gray-700 pb-2">
                 Stack Frame (printf)
             </div>
             
             <div className="flex flex-col gap-1 font-mono text-sm">
                 {/* Header Row */}
                 <div className="grid grid-cols-[1fr_2fr] text-xs text-gray-500 mb-2 px-2">
                     <div>Offset</div>
                     <div>Value</div>
                 </div>

                 {stackItems.map((val, idx) => {
                     // Reverse index for stack address visualization (High to Low)
                     const offset = (idx + 1) * 4;
                     const isBeingRead = idx === readIndex;
                     
                     return (
                         <div key={idx} className={`grid grid-cols-[1fr_2fr] p-2 rounded transition-all duration-300 ${isBeingRead ? 'bg-red-900/30 border border-red-500/50' : 'bg-[#252526] border border-transparent'}`}>
                             <div className="text-gray-500 text-xs flex items-center">
                                 ESP + {offset}
                             </div>
                             <div className={`${isBeingRead ? 'text-red-300 font-bold' : 'text-blue-300'}`}>
                                 {val}
                             </div>
                             {isBeingRead && (
                                <div className="absolute left-[-10px] text-red-500 animate-pulse">
                                    <ArrowUp className="rotate-90" size={16}/>
                                </div>
                             )}
                         </div>
                     )
                 })}
                  <div className="text-center text-xs text-gray-600 mt-2">... (Lower Addresses)</div>
             </div>
        </div>

        {/* Console Output */}
        <div className="flex-1 w-full flex flex-col">
            <div className="bg-black rounded-lg border border-slate-700 overflow-hidden shadow-2xl h-64 flex flex-col">
                <div className="bg-slate-800 px-3 py-1 flex items-center gap-2 text-xs text-slate-300">
                    <Terminal size={12} />
                    <span>Terminal / Stdout</span>
                </div>
                <div className="p-4 font-mono text-green-400 text-sm flex-1 whitespace-pre-wrap">
                    <span className="text-slate-500">$ ./vuln_program "%x %x"</span>
                    <br/>
                    {step.fmtOutput}
                    <span className="animate-pulse">_</span>
                </div>
            </div>
            
            <div className="mt-4 p-4 bg-yellow-900/20 border border-yellow-700/50 rounded text-xs text-yellow-200 leading-relaxed">
                <strong>Mechanism:</strong> <br/>
                `printf` expects arguments on the stack corresponding to `%` specifiers. <br/>
                If you provide `%x` without an argument, `printf` blindly reads the next value from the stack, leaking memory!
            </div>
        </div>

    </div>
  );
};