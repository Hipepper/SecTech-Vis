import React from 'react';
import { AnimationStep } from '../types';
import { Layers, ArrowRight, Terminal, Cpu } from 'lucide-react';

interface ROPVisualizerProps {
  step: AnimationStep;
}

export const ROPVisualizer: React.FC<ROPVisualizerProps> = ({ step }) => {
  
  const stack = step.ropStack || [];
  const regs = step.ropRegs || { rip: '0x00401000', rdi: '0x00000000', rsp: '0x7FFFFFFF' };

  return (
    <div className="flex flex-col gap-6 w-full max-w-4xl mx-auto p-4 bg-slate-800/50 rounded-xl border border-slate-700">
      
      {/* Top Section: Stack and Regs */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 lg:gap-8">
          
          {/* Left: The Stack View */}
          <div className="flex flex-col gap-2">
              <div className="text-xs text-gray-400 uppercase font-bold flex items-center gap-2 mb-2">
                  <Layers size={14} className="text-blue-400" /> Stack (RSP)
              </div>
              <div className="bg-[#1e1e1e] border border-gray-600 rounded-sm overflow-hidden flex flex-col relative">
                  {stack.map((item, idx) => (
                      <div key={idx} className={`p-2 border-b border-gray-700 font-mono text-sm flex justify-between items-center transition-all duration-300 
                          ${item.active ? 'bg-yellow-900/30 text-yellow-200' : ''}
                          ${item.type === 'padding' ? 'text-slate-600' : ''}
                          ${item.type === 'gadget' ? 'text-purple-300' : ''}
                          ${item.type === 'data' ? 'text-green-300' : ''}
                          ${item.type === 'target' ? 'text-red-300' : ''}
                      `}>
                          <div className="flex flex-col">
                              <span className="text-[10px] text-slate-500 mb-0.5">{item.type.toUpperCase()}</span>
                              <span className="font-bold">{item.value}</span>
                          </div>
                          <span className="text-xs text-slate-400">{item.label}</span>
                          
                          {/* RSP Indicator */}
                          {item.active && (
                              <div className="absolute left-0 w-1 h-10 bg-yellow-500"></div>
                          )}
                      </div>
                  ))}
                  <div className="p-1 text-center text-[10px] text-slate-600 bg-[#151515]">High Address</div>
              </div>
          </div>

          {/* Right: CPU State & Execution */}
          <div className="flex flex-col gap-4">
              
              {/* Registers */}
              <div className="bg-[#1e1e1e] p-3 rounded border border-gray-600 flex flex-col gap-2">
                  <div className="text-xs text-gray-400 uppercase font-bold flex items-center gap-2">
                      <Cpu size={14} className="text-green-400" /> Registers
                  </div>
                  <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-xs sm:text-sm">
                      <div className="text-yellow-500 font-bold">RIP</div>
                      <div className="bg-black/30 px-2 rounded text-slate-300 border border-slate-700">{regs.rip}</div>
                      
                      <div className="text-blue-500 font-bold">RSP</div>
                      <div className="bg-black/30 px-2 rounded text-slate-300 border border-slate-700">{regs.rsp}</div>
                      
                      <div className="text-green-500 font-bold">RDI</div>
                      <div className="bg-black/30 px-2 rounded text-slate-300 border border-slate-700">{regs.rdi}</div>
                  </div>
              </div>

              {/* Action/Gadget View */}
              <div className="bg-slate-900 border border-slate-700 rounded-lg p-4 flex flex-col gap-2 min-h-[100px] justify-center items-center text-center relative overflow-hidden flex-1">
                   {step.ropAction === 'overflow' && (
                       <div className="text-red-400 font-bold animate-pulse text-sm">Creating ROP Chain...</div>
                   )}
                   {step.ropAction === 'ret' && (
                       <div className="flex flex-col items-center gap-1">
                           <span className="text-[10px] text-slate-500">Instruction</span>
                           <span className="text-lg font-mono text-yellow-400 font-bold">RET</span>
                           <span className="text-[10px] text-slate-400 max-w-[180px]">Pops from Stack -》 RIP</span>
                           <ArrowRight className="rotate-90 text-slate-600" size={16} />
                       </div>
                   )}
                   {step.ropAction === 'pop' && (
                       <div className="flex flex-col items-center gap-1">
                           <span className="text-[10px] text-slate-500">Gadget</span>
                           <span className="text-lg font-mono text-purple-400 font-bold">POP RDI; RET</span>
                           <span className="text-[10px] text-slate-400 max-w-[180px]">Load Arg -》 RDI</span>
                       </div>
                   )}
                   {step.ropAction === 'exec' && (
                       <div className="flex flex-col items-center gap-1">
                           <span className="text-[10px] text-slate-500">Target</span>
                           <span className="text-lg font-mono text-red-400 font-bold">system(RDI)</span>
                           <div className="flex items-center gap-2 mt-1 bg-black px-2 py-1 rounded text-green-400 font-mono text-[10px] border border-green-900">
                               <Terminal size={10} />
                               <span>sh-4.4$ _</span>
                           </div>
                       </div>
                   )}
              </div>
              
              <div className="text-[10px] text-slate-500 text-center bg-black/20 p-2 rounded border border-slate-800">
                  <span className="font-bold text-slate-400">ROP:</span> Chain gadgets to bypass NX.
              </div>
          </div>
      </div>

    </div>
  );
};
