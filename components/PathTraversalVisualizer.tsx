import React from 'react';
import { AnimationStep } from '../types';
import { Globe, Server, Folder, FileText, ShieldAlert, ArrowDown, ArrowRight } from 'lucide-react';

interface PathTraversalVisualizerProps {
  step: AnimationStep;
}

export const PathTraversalVisualizer: React.FC<PathTraversalVisualizerProps> = ({ step }) => {
  const current = step.ptStep || 'input';
  const showClient = ['input', 'request'].includes(current);
  const showServer = ['request', 'normalize', 'resolve', 'read', 'response'].includes(current);
  const showFs = ['resolve', 'read', 'response'].includes(current);
  const showResponse = current === 'response';

  return (
    <div className="flex flex-col gap-8 w-full max-w-6xl mx-auto p-4">
      {/* 1. CLIENT */}
      <div className={`
          flex flex-col p-6 rounded-xl border-2 transition-all duration-500 relative min-h-[160px]
          ${showClient ? 'border-blue-500 bg-blue-900/10 opacity-100' : 'border-slate-700 bg-slate-800/30 opacity-60'}
      `}>
        <div className="flex items-center gap-2 mb-4 text-slate-300 font-bold border-b border-slate-600 pb-2">
          <Globe size={20} className="text-blue-400" /> Client (Browser)
        </div>
        <div className="bg-white rounded p-3 flex items-center gap-3 shadow-md">
          <div className="text-[10px] text-slate-500 uppercase font-bold">Download File</div>
          <div className="flex-1 text-sm font-mono text-slate-700 overflow-hidden text-ellipsis whitespace-nowrap">
            /download?file=<span className="font-bold text-red-600">{step.ptInputPath}</span>
          </div>
        </div>
        {current === 'request' && (
          <div className="absolute -bottom-6 left-1/2 -translate-x-1/2 z-10 text-blue-500 animate-bounce">
            <ArrowDown size={40} strokeWidth={3} />
          </div>
        )}
      </div>

      {/* 2. SERVER */}
      <div className={`
          flex flex-col p-6 rounded-xl border-2 transition-all duration-500 relative min-h-[180px]
          ${showServer ? 'border-purple-500 bg-purple-900/10 opacity-100 shadow-xl' : 'border-slate-700 bg-slate-800/30 opacity-60'}
      `}>
        <div className="flex items-center gap-2 mb-4 text-slate-300 font-bold border-b border-slate-600 pb-2">
          <Server size={20} className="text-purple-400" /> Web Server
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-[#1e1e1e] p-4 rounded border border-slate-600 font-mono text-sm overflow-x-auto shadow-inner">
            <div className="text-slate-500 mb-2">// download.js</div>
            <div className="text-yellow-300">const base = '{step.ptBasePath}';</div>
            <div className="text-blue-300">const file = '{step.ptInputPath}';</div>
            <div className="text-slate-400 mt-2 italic">// VULNERABLE join without validation</div>
            <div className="text-green-300 whitespace-pre-wrap break-all mt-1 p-2 bg-black/20 rounded border border-white/5">
              const filePath = base + '/' + file;
            </div>
            <div className="text-green-300 mt-1">content = fs.readFileSync(filePath)</div>
          </div>

          <div className="bg-slate-900 p-3 rounded border border-slate-600">
            <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">Normalization</div>
            <div className="text-xs font-mono text-slate-300">
              <div>normalized: <span className="text-blue-300">{step.ptNormalizedPath || '—'}</span></div>
              <div>resolved: <span className="text-blue-300">{step.ptFinalPath || '—'}</span></div>
            </div>
            {current === 'normalize' && (
              <div className="mt-2 text-xs text-purple-200 bg-purple-900/40 px-3 py-1 rounded border border-purple-500/30 animate-pulse">
                Attempting normalization...
              </div>
            )}
          </div>

          <div className="bg-slate-900 p-3 rounded border border-slate-600">
            <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">Base Check</div>
            <div className="text-xs font-mono text-slate-300">
              base: <span className="text-blue-300">{step.ptBasePath}</span>
            </div>
            {current === 'resolve' && (
              <div className="mt-2 text-xs text-red-200 bg-red-900/40 px-3 py-1 rounded border border-red-500/30">
                <ShieldAlert size={12} className="inline mr-1"/> Escapes base directory!
              </div>
            )}
          </div>
        </div>

        {['resolve','read'].includes(current) && (
          <div className="absolute -bottom-6 left-1/2 -translate-x-1/2 z-10 text-purple-500 animate-bounce">
            <ArrowDown size={40} strokeWidth={3} />
          </div>
        )}
      </div>

      {/* 3. FILESYSTEM */}
      <div className={`
          flex flex-col p-6 rounded-xl border-2 transition-all duration-500 min-h-[180px]
          ${showFs ? 'border-red-500 bg-red-900/10 opacity-100' : 'border-slate-700 bg-slate-800/30 opacity-60'}
      `}>
        <div className="flex items-center gap-2 mb-4 text-slate-300 font-bold border-b border-slate-600 pb-2">
          <Folder size={20} className="text-red-400" /> File System
        </div>

        <div className="flex items-start gap-6">
          <div className="flex-1 bg-white rounded p-3 shadow-inner">
            <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">Resolved Path</div>
            <div className="font-mono text-sm text-slate-800 break-all border border-slate-300 p-2 rounded">
              {step.ptFinalPath || '—'}
            </div>
          </div>
          <div className="flex-1 bg-white rounded p-3 shadow-inner">
            <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">File Content</div>
            <div className="font-mono text-xs text-slate-800 whitespace-pre-wrap border border-slate-300 p-2 rounded min-h-[100px]">
              {step.ptFileContent || 'Waiting for read...'}
            </div>
          </div>
        </div>
      </div>

      {/* FLOW ARROWS */}
      <div className="relative h-10 hidden md:block">
        <div className={`absolute left-[20%] top-0 transition-all duration-700 ${showClient && showServer ? 'opacity-100 translate-y-2' : 'opacity-0'}`}>
          <ArrowRight size={24} className="text-blue-500 rotate-90" />
        </div>
        <div className={`absolute right-[33%] -top-4 w-1/3 h-4 border-t-2 border-dashed border-slate-600 rounded-t-full transition-all duration-500 ${showResponse ? 'opacity-100' : 'opacity-0'}`}></div>
      </div>

      {/* 4. RESPONSE */}
      <div className={`
          flex flex-col p-6 rounded-xl border-2 transition-all duration-500 min-h-[120px]
          ${showResponse ? 'border-green-500 bg-green-900/10 opacity-100' : 'border-slate-700 bg-slate-800/30 opacity-60'}
      `}>
        <div className="flex items-center gap-2 mb-2 text-slate-300 font-bold">
          <FileText size={18} className="text-green-400"/> HTTP Response
        </div>
        <div className="bg-black text-green-300 text-xs font-mono p-2 rounded border border-slate-700">
          {step.ptFileContent ? step.ptFileContent.slice(0, 120) + '...' : '—'}
        </div>
      </div>
    </div>
  );
};