import React from 'react';
import { AnimationStep } from '../types';
import { ArrowRight, Database, AlertTriangle } from 'lucide-react';

interface HeapVisualizerProps {
  step: AnimationStep;
}

export const HeapVisualizer: React.FC<HeapVisualizerProps> = ({ step }) => {
    
  const getHeaderStyle = (chunk: number) => {
      if (chunk === 2 && step.highlightRegion === 'chunk2_header' && step.isCorrupted) {
          return 'bg-red-900/80 border-red-500 text-red-200 ring-2 ring-red-500';
      }
      return 'bg-purple-900/30 border-purple-500/50 text-purple-200';
  };

  const getChunkStyle = (chunk: number) => {
      if (chunk === 1 && step.highlightRegion === 'chunk1') {
          return 'ring-2 ring-blue-400';
      }
      return '';
  };

  const renderDataBytes = (content: string = "") => {
     // Limit display to fit visually
     const display = content.length > 0 ? content : "................";
     return (
         <div className="font-mono break-all text-sm tracking-widest text-slate-300">
             {display.slice(0, 32)}
         </div>
     )
  }

  return (
    <div className="flex flex-col items-center gap-6 w-full max-w-2xl mx-auto p-6 bg-slate-800/50 rounded-xl border border-slate-700 overflow-hidden">
      <div className="flex w-full justify-between text-xs text-slate-400 uppercase tracking-widest font-bold">
          <span>Low Address</span>
          <span>High Address</span>
      </div>

      <div className="flex flex-row gap-1 w-full overflow-x-auto p-4 border-2 border-dashed border-slate-700 rounded-lg bg-black/20 min-h-[160px] relative">
         
         {/* Chunk 1 */}
         <div className={`flex flex-col flex-1 min-w-[140px] rounded border border-slate-600 transition-all duration-500 ${getChunkStyle(1)}`}>
             {/* Header */}
             <div className="h-8 bg-purple-900/30 border-b border-slate-600 flex items-center px-2 text-xs text-purple-300 gap-2">
                 <Database size={10} />
                 <span>Header (Sz: 16)</span>
             </div>
             {/* Data */}
             <div className="flex-1 bg-slate-900 p-2 break-all relative group">
                  <span className="text-xs text-slate-500 absolute top-1 right-1">chunk1</span>
                  {renderDataBytes(step.heapChunk1Content)}
                  {step.highlightRegion === 'chunk1' && (
                      <div className="absolute inset-0 bg-blue-500/10 pointer-events-none animate-pulse"></div>
                  )}
             </div>
         </div>

         {/* Arrow representing overflow if applicable */}
         {step.isCorrupted && step.highlightRegion === 'chunk2_header' && (
             <div className="absolute left-[45%] top-1/2 -translate-y-1/2 z-10 text-red-500 animate-bounce">
                <ArrowRight size={32} />
             </div>
         )}

         {/* Chunk 2 */}
         <div className={`flex flex-col flex-1 min-w-[140px] rounded border border-slate-600 transition-all duration-500 relative`}>
             {/* Header */}
             <div className={`h-8 border-b border-slate-600 flex items-center px-2 text-xs gap-2 transition-colors duration-300 ${getHeaderStyle(2)}`}>
                 <Database size={10} />
                 <span className={step.isCorrupted && step.highlightRegion === 'chunk2_header' ? 'font-bold' : ''}>
                    {step.heapChunk2Header || "Header (Sz: 16)"}
                 </span>
             </div>
             {/* Data */}
             <div className="flex-1 bg-slate-900 p-2 break-all relative">
                 <span className="text-xs text-slate-500 absolute top-1 right-1">chunk2</span>
                  {renderDataBytes(step.heapChunk2Content)}
             </div>
         </div>

      </div>

      <div className="w-full text-center">
          {step.isCorrupted ? (
              <div className="text-red-400 text-sm font-bold flex items-center justify-center gap-2">
                  <AlertTriangle size={16} />
                  Heap Metadata Corrupted! Next free() will crash or allow write-what-where.
              </div>
          ) : (
              <div className="text-green-500 text-sm flex items-center justify-center gap-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                  Heap State Valid
              </div>
          )}
      </div>

    </div>
  );
};