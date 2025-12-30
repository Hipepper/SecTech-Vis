import React from 'react';
import { GitFork, ArrowDown } from 'lucide-react';

const FlowStep: React.FC<{ title: string; meta: string; type: 'normal' | 'attack'; isLast?: boolean }> = ({ title, meta, type, isLast }) => (
    <div className="relative flex flex-col items-center w-full">
        <div className={`w-full p-2 rounded-lg border-l-4 shadow-sm transition-all hover:scale-[1.02] 
            ${type === 'normal' 
                ? 'bg-green-900/10 border-green-500/50 hover:bg-green-900/20' 
                : 'bg-red-900/10 border-red-500/50 hover:bg-red-900/20'}`
        }>
            <div className={`font-bold text-xs mb-0.5 ${type === 'normal' ? 'text-green-300' : 'text-red-300'}`}>
                {title}
            </div>
            <div className="text-[10px] font-mono text-slate-400 whitespace-pre-wrap leading-tight">
                {meta}
            </div>
        </div>
        {!isLast && (
            <div className="h-4 flex items-center justify-center">
                <ArrowDown size={12} className={type === 'normal' ? 'text-green-700' : 'text-red-700'} />
            </div>
        )}
    </div>
);

export const ROPFlowChart: React.FC = () => {
  return (
    <div className="flex flex-col h-full bg-slate-800/30 rounded-xl border border-slate-700 p-4 overflow-y-auto">
        <div className="flex items-center gap-2 mb-4 pb-2 border-b border-slate-700/50">
            <GitFork size={16} className="text-blue-400" />
            <h3 className="text-sm font-bold text-slate-200">Flow Comparison</h3>
        </div>

        <div className="flex flex-col gap-6">
            
            {/* Normal Flow */}
            <div className="flex flex-col">
                <div className="flex items-center gap-2 mb-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-green-500"></div>
                    <h4 className="text-[10px] font-bold text-green-400 uppercase tracking-widest">Normal Flow</h4>
                </div>
                <div className="flex flex-col bg-[#151515] p-3 rounded-lg border border-slate-800/50">
                    <FlowStep 
                        title="1. Function Call" 
                        type="normal"
                        meta={`Call vuln()\nStack: [Ret: 0x00401234]`}
                    />
                    <FlowStep 
                        title="2. Safe Input" 
                        type="normal"
                        meta={`gets(buf)\nBuffer filled safely.`}
                    />
                    <FlowStep 
                        title="3. Return" 
                        type="normal"
                        meta={`ret -> POP RIP\nRIP = 0x00401234`}
                    />
                    <FlowStep 
                        title="4. Resume Main" 
                        type="normal"
                        meta={`Continue execution.`}
                        isLast
                    />
                </div>
            </div>

            {/* Attack Flow */}
            <div className="flex flex-col">
                <div className="flex items-center gap-2 mb-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></div>
                    <h4 className="text-[10px] font-bold text-red-400 uppercase tracking-widest">ROP Attack Flow</h4>
                </div>
                <div className="flex flex-col bg-[#151515] p-3 rounded-lg border border-slate-800/50">
                    <FlowStep 
                        title="1. Function Call" 
                        type="attack"
                        meta={`Call vuln()\nStack: [Ret saved]`}
                    />
                    <FlowStep 
                        title="2. Overflow" 
                        type="attack"
                        meta={`gets(buf)\nOverwrite Ret -> Gadget 1`}
                    />
                    <FlowStep 
                        title="3. Gadget 1" 
                        type="attack"
                        meta={`ret -> 0x00401105\npop rdi; ret\nRDI = "/bin/sh"`}
                    />
                    <FlowStep 
                        title="4. Target" 
                        type="attack"
                        meta={`ret -> 0x00401040\nsystem(RDI)\nSpawns Shell!`}
                        isLast
                    />
                </div>
            </div>

        </div>
    </div>
  );
};
