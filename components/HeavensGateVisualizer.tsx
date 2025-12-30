import React from 'react';
import { AnimationStep } from '../types';
import { Cpu, Lock, Unlock, ArrowRight, ShieldAlert } from 'lucide-react';

interface HeavensGateVisualizerProps {
  step: AnimationStep;
}

export const HeavensGateVisualizer: React.FC<HeavensGateVisualizerProps> = ({ step }) => {
  
  const mode = step.hgMode || 'x86';
  const cs = step.hgCS || '0x23';
  const regs = step.hgRegs || { ax: '00000000', ip: '00401000', sp: '0019FFCC' };

  return (
    <div className="flex flex-col w-full max-w-4xl mx-auto p-4 gap-6">
        
        {/* Main CPU State Container */}
        <div className="relative bg-slate-900 border border-slate-700 rounded-xl p-8 overflow-hidden min-h-[300px] flex items-center justify-center transition-all duration-700">
            
            {/* Background Effects */}
            <div className={`absolute inset-0 transition-opacity duration-1000 ${mode === 'x64' ? 'bg-purple-900/20' : 'bg-blue-900/10'}`}></div>
            {mode === 'x64' && (
                <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')] opacity-10"></div>
            )}

            {/* The Gate (Visual Separator) */}
            <div className="absolute inset-y-0 left-1/2 w-1 bg-gradient-to-b from-transparent via-slate-600 to-transparent -translate-x-1/2"></div>
            
            {/* Left Side: 32-bit World */}
            <div className={`absolute left-0 top-0 bottom-0 w-1/2 flex flex-col items-center justify-center p-4 transition-all duration-500 ${mode === 'x64' ? 'opacity-30 blur-sm grayscale' : 'opacity-100'}`}>
                <div className="text-4xl font-black text-blue-500/20 absolute top-4 left-4 select-none">32-bit</div>
                <div className="bg-[#1e1e1e] border-2 border-blue-500/30 p-4 rounded-lg shadow-[0_0_20px_rgba(59,130,246,0.2)] w-64">
                    <div className="flex items-center gap-2 mb-4 border-b border-gray-700 pb-2">
                        <Cpu className="text-blue-400" size={20} />
                        <span className="font-bold text-blue-100">WoW64 Mode</span>
                    </div>
                    <div className="font-mono text-xs space-y-2 text-blue-200">
                        <div className="flex justify-between">
                            <span className="text-gray-500">CS</span>
                            <span className="bg-slate-800 px-1 rounded text-yellow-400">0x23</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-gray-500">EAX</span>
                            <span>{regs.ax.slice(-8)}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-gray-500">ESP</span>
                            <span>{regs.sp.slice(-8)}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-gray-500">EIP</span>
                            <span>{regs.ip.slice(-8)}</span>
                        </div>
                    </div>
                </div>
                <div className="mt-8 text-center">
                    <div className="flex items-center gap-2 text-xs text-red-400 bg-red-900/20 px-3 py-1 rounded-full border border-red-500/30">
                        <ShieldAlert size={12} />
                        <span>AV Hooks Active</span>
                    </div>
                </div>
            </div>

            {/* Right Side: 64-bit World */}
            <div className={`absolute right-0 top-0 bottom-0 w-1/2 flex flex-col items-center justify-center p-4 transition-all duration-500 ${mode === 'x86' ? 'opacity-30 blur-sm grayscale' : 'opacity-100'}`}>
                <div className="text-4xl font-black text-purple-500/20 absolute top-4 right-4 select-none">64-bit</div>
                <div className="bg-[#1e1e1e] border-2 border-purple-500/30 p-4 rounded-lg shadow-[0_0_30px_rgba(168,85,247,0.3)] w-72 scale-110">
                    <div className="flex items-center gap-2 mb-4 border-b border-gray-700 pb-2">
                        <Cpu className="text-purple-400" size={20} />
                        <span className="font-bold text-purple-100">Native Mode</span>
                    </div>
                    <div className="font-mono text-xs space-y-2 text-purple-200">
                        <div className="flex justify-between">
                            <span className="text-gray-500">CS</span>
                            <span className="bg-slate-800 px-1 rounded text-yellow-400">0x33</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-gray-500">RAX</span>
                            <span>{regs.ax}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-gray-500">RSP</span>
                            <span>{regs.sp}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-gray-500">RIP</span>
                            <span>{regs.ip}</span>
                        </div>
                    </div>
                </div>
                <div className="mt-8 text-center">
                    <div className="flex items-center gap-2 text-xs text-green-400 bg-green-900/20 px-3 py-1 rounded-full border border-green-500/30">
                        <Unlock size={12} />
                        <span>Hooks Bypassed</span>
                    </div>
                </div>
            </div>

            {/* Transition Arrow */}
            <div className={`absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 transition-all duration-500 z-10 
                ${mode === 'x64' ? 'rotate-0 opacity-100 scale-125' : 'opacity-0 scale-50'}`}>
                <div className="bg-yellow-500 text-black p-2 rounded-full shadow-[0_0_20px_rgba(234,179,8,0.8)] animate-pulse">
                    <ArrowRight size={24} strokeWidth={3} />
                </div>
            </div>

        </div>

        {/* Info Box */}
        <div className="flex justify-between items-center bg-black/30 p-4 rounded-lg border border-slate-700">
            <div className="flex flex-col gap-1">
                <span className="text-xs text-gray-500 uppercase font-bold">Code Segment (CS) Selector</span>
                <span className="font-mono text-2xl text-yellow-500 font-bold">{cs}</span>
                <span className="text-xs text-gray-400">{cs === '0x23' ? '32-bit Compatibility Segment' : '64-bit Long Mode Segment'}</span>
            </div>
            
            <div className="h-10 w-px bg-slate-700"></div>

            <div className="flex flex-col gap-1 items-end text-right">
                <span className="text-xs text-gray-500 uppercase font-bold">Current Instruction</span>
                <span className="font-mono text-lg text-green-400">{step.hgInstruction || "NOP"}</span>
            </div>
        </div>
    </div>
  );
};
