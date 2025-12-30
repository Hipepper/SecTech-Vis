import React from 'react';
import { AnimationStep } from '../types';
import { Calculator, ArrowDown, AlertTriangle, Database } from 'lucide-react';

interface IntegerOverflowVisualizerProps {
  step: AnimationStep;
}

export const IntegerOverflowVisualizer: React.FC<IntegerOverflowVisualizerProps> = ({ step }) => {
  
  const valA = step.intMathA || 0;
  const valB = step.intMathB || 0;
  const resultReal = step.intMathReal || 0;
  const resultWrapped = step.intMathResult || 0;
  
  // Helper to get binary string
  const toBinary = (num: number, bits: number) => num.toString(2).padStart(bits, '0');

  const binaryString = toBinary(resultReal, 9); // Show 9 bits to demonstrate the overflow bit
  const overflowBit = binaryString.length > 8 ? binaryString.slice(0, binaryString.length - 8) : '0';
  const keptBits = binaryString.slice(-8);

  return (
    <div className="flex flex-col gap-6 w-full max-w-2xl mx-auto p-6 bg-slate-800/50 rounded-xl border border-slate-700">
        
        {/* Arithmetic Section */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Calculation */}
            <div className="bg-[#1e1e1e] p-4 rounded border border-gray-600 flex flex-col gap-2 relative">
                <div className="text-xs text-gray-500 uppercase font-bold flex items-center gap-2">
                    <Calculator size={14} /> Size Calculation
                </div>
                <div className="font-mono text-lg text-slate-300 flex justify-between items-center px-4">
                    <span>len</span> <span>{valA}</span>
                </div>
                <div className="font-mono text-lg text-slate-300 flex justify-between items-center px-4 border-b border-gray-700 pb-2">
                    <span>overhead</span> <span>+ {valB}</span>
                </div>
                <div className="font-mono text-xl text-blue-400 flex justify-between items-center px-4 pt-1">
                    <span>result</span> <span>{resultReal}</span>
                </div>
                
                {resultReal > 255 && (
                    <div className="absolute top-2 right-2 text-red-500 animate-pulse">
                        <AlertTriangle size={20} />
                    </div>
                )}
            </div>

            {/* Binary View (The Register) */}
            <div className="bg-[#1e1e1e] p-4 rounded border border-gray-600 flex flex-col gap-2">
                 <div className="text-xs text-gray-500 uppercase font-bold flex items-center gap-2">
                    <Database size={14} /> 8-Bit Register
                </div>
                <div className="flex flex-col items-center justify-center h-full">
                    <div className="flex items-center gap-1 font-mono text-xl">
                        {/* Overflow Bit */}
                        <div className={`flex flex-col items-center ${resultReal > 255 ? 'opacity-100' : 'opacity-20'}`}>
                             <span className="text-[10px] text-red-500">Lost</span>
                             <span className="text-red-500 font-bold border border-red-500/50 px-1 bg-red-900/20 rounded">{overflowBit}</span>
                        </div>
                        <span className="text-slate-600">|</span>
                        {/* Kept Bits */}
                        <div className="flex flex-col items-center">
                             <span className="text-[10px] text-blue-500">Stored</span>
                             <div className="flex gap-0.5">
                                 {keptBits.split('').map((bit, i) => (
                                     <span key={i} className={`px-0.5 ${bit === '1' ? 'text-blue-200' : 'text-slate-600'}`}>{bit}</span>
                                 ))}
                             </div>
                        </div>
                    </div>
                    <div className="mt-2 text-sm text-slate-400">
                        Decimal Value: <span className="text-white font-bold">{resultWrapped}</span>
                    </div>
                </div>
            </div>
        </div>

        {/* Memory Allocation Consequence */}
        <div className="bg-slate-900/50 p-4 rounded border border-slate-700 relative min-h-[120px] flex items-center justify-center">
             <div className="absolute top-2 left-2 text-xs text-slate-500">Heap State</div>
             
             {step.intBufferState === 'none' && (
                 <span className="text-slate-600 italic">Waiting for allocation...</span>
             )}

             {step.intBufferState !== 'none' && (
                 <div className="flex items-center gap-4">
                     {/* The Allocated Buffer */}
                     <div className="flex flex-col items-center gap-1">
                         <span className="text-xs text-blue-400">malloc({resultWrapped})</span>
                         <div className={`w-16 h-16 border-2 border-blue-500 bg-blue-900/20 rounded flex items-center justify-center text-xs text-center transition-all duration-500 ${step.intBufferState === 'overflow' ? 'ring-4 ring-red-500 bg-red-900/50' : ''}`}>
                             Buffer<br/>({resultWrapped} bytes)
                         </div>
                     </div>

                     {step.intBufferState === 'overflow' && (
                         <>
                            <div className="text-red-500 animate-pulse">
                                <ArrowDown size={24} className="-rotate-90" />
                            </div>
                            {/* The Data being copied */}
                            <div className="flex flex-col items-center gap-1">
                                <span className="text-xs text-red-400">memcpy(..., {valA})</span>
                                <div className="w-32 h-16 border-2 border-red-500 bg-red-900/20 rounded flex items-center justify-center text-xs text-center relative overflow-hidden">
                                     User Data<br/>({valA} bytes)
                                     <div className="absolute inset-0 bg-red-500/10 animate-pulse"></div>
                                </div>
                            </div>
                         </>
                     )}
                 </div>
             )}
        </div>
        
        {step.intBufferState === 'overflow' && (
             <div className="text-red-400 text-xs text-center font-bold">
                 CRITICAL: Writing {valA} bytes into a {resultWrapped} byte buffer causes a massive Heap Overflow!
             </div>
        )}

    </div>
  );
};
