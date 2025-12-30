import React from 'react';
import { AnimationStep } from '../types';
import { ArrowRight, Box, Cpu, FileCode, Play, Pause, Skull, XCircle } from 'lucide-react';

interface ProcessHollowingVisualizerProps {
  step: AnimationStep;
}

export const ProcessHollowingVisualizer: React.FC<ProcessHollowingVisualizerProps> = ({ step }) => {
  
  const state = step.phState || 'idle';
  const target = step.phTarget || { name: 'svchost.exe', status: 'Running', memoryContent: 'LegitCode', entryPoint: '0x401000' };

  return (
    <div className="flex flex-col gap-8 w-full max-w-5xl mx-auto p-4">
        
        {/* Actors Row */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-12 items-center">
            
            {/* Attacker / Source */}
            <div className="flex flex-col gap-4 p-6 rounded-xl border border-slate-700 bg-slate-800/50 opacity-80">
                <div className="flex items-center gap-2 border-b border-slate-700 pb-2">
                    <Skull className="text-red-500" size={20} />
                    <span className="font-bold text-slate-200">Attacker (Malware)</span>
                </div>
                <div className="bg-slate-900 p-4 rounded border border-slate-600 flex flex-col items-center gap-2">
                    <FileCode className="text-red-400" size={32} />
                    <span className="text-xs font-mono text-slate-400">Payload.exe</span>
                    <span className="text-[10px] text-slate-500">(Source Bytes)</span>
                </div>
                {state === 'write' && (
                    <div className="absolute left-1/2 -translate-x-1/2 md:left-auto md:translate-x-0 md:right-[-24px] top-1/2 z-20">
                        <div className="bg-red-600 p-2 rounded-full animate-pulse shadow-[0_0_15px_rgba(220,38,38,0.6)]">
                            <ArrowRight className="text-white" size={24} />
                        </div>
                    </div>
                )}
            </div>

            {/* Target Process Container */}
            <div className={`relative flex flex-col gap-4 p-6 rounded-xl border-2 transition-all duration-500
                ${target.status === 'Hollowed' ? 'border-red-500 bg-red-900/10' : 'border-blue-500 bg-blue-900/10'}
            `}>
                <div className="flex items-center justify-between border-b border-slate-700 pb-2">
                    <div className="flex items-center gap-2">
                        <Box className={target.status === 'Hollowed' ? 'text-red-400' : 'text-blue-400'} size={20} />
                        <span className="font-bold text-slate-200">{target.name} (PID: 1337)</span>
                    </div>
                    <div className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase
                        ${target.status === 'Suspended' ? 'bg-yellow-500 text-black' : ''}
                        ${target.status === 'Running' ? 'bg-green-500 text-black' : ''}
                        ${target.status === 'Hollowed' ? 'bg-red-500 text-white animate-pulse' : ''}
                    `}>
                        {target.status}
                    </div>
                </div>

                {/* Internal Memory View */}
                <div className="relative bg-black/40 p-4 rounded border border-slate-600 min-h-[160px] flex flex-col items-center justify-center gap-2 overflow-hidden">
                    <span className="text-xs text-slate-500 absolute top-2 left-2">Memory Space (BaseAddr)</span>
                    
                    {/* The Memory Block */}
                    {target.memoryContent === 'LegitCode' && (
                        <div className="w-full h-20 bg-blue-600/30 border border-blue-500 rounded flex items-center justify-center text-blue-200 font-mono text-sm animate-in fade-in zoom-in duration-300">
                            [ Original PE Image ]
                        </div>
                    )}
                    {target.memoryContent === 'Empty' && (
                        <div className="w-full h-20 border-2 border-dashed border-slate-600 rounded flex items-center justify-center text-slate-500 font-mono text-sm">
                            &lt; Unmapped / Empty &gt;
                        </div>
                    )}
                    {target.memoryContent === 'MalPayload' && (
                        <div className="w-full h-20 bg-red-600/30 border border-red-500 rounded flex items-center justify-center text-red-200 font-mono text-sm animate-in zoom-in duration-300">
                            [ Malicious Payload ]
                        </div>
                    )}

                    {/* Thread / CPU Context */}
                    <div className="mt-4 w-full flex items-center justify-between px-4 py-2 bg-slate-800 rounded border border-slate-600">
                        <div className="flex items-center gap-2">
                            <Cpu size={16} className="text-yellow-400" />
                            <span className="text-xs text-slate-300">Main Thread</span>
                        </div>
                        <div className="flex flex-col items-end">
                            <span className="text-[10px] text-slate-500">Entry Point (EAX/RCX)</span>
                            <span className={`text-xs font-mono font-bold ${state === 'resume' ? 'text-red-400' : 'text-slate-200'}`}>
                                {target.entryPoint}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        {/* Status Bar / Explainer */}
        <div className="bg-[#1e1e1e] p-4 rounded-lg border border-slate-700 flex items-center justify-center gap-4 text-sm text-slate-300">
            {state === 'create' && <span>Creating suspended process... It looks innocent to AV.</span>}
            {state === 'unmap' && <span className="text-yellow-400 flex items-center gap-2"><XCircle size={16}/> Unmapping legitimate code section (Hollowing).</span>}
            {state === 'write' && <span className="text-red-400">Writing malicious code into the empty shell.</span>}
            {state === 'resume' && <span className="text-green-400 font-bold flex items-center gap-2"><Play size={16}/> Resuming thread. Malware runs as "svchost.exe"!</span>}
            {state === 'idle' && <span>Ready to start.</span>}
        </div>

    </div>
  );
};
