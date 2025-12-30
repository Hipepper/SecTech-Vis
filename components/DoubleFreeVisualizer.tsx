import React from 'react';
import { AnimationStep } from '../types';
import { Recycle, Box, AlertTriangle, ArrowRight } from 'lucide-react';

interface DoubleFreeVisualizerProps {
  step: AnimationStep;
}

export const DoubleFreeVisualizer: React.FC<DoubleFreeVisualizerProps> = ({ step }) => {
  
  const binList = step.dfBinList || [];
  const chunkState = step.dfChunkState || 'alloc';

  return (
    <div className="flex flex-col gap-8 w-full max-w-2xl mx-auto p-6 bg-slate-800/50 rounded-xl border border-slate-700">
      
      <div className="flex justify-between items-start gap-8">
          
          {/* Fastbin / Free List Visualization */}
          <div className="flex-1 bg-[#1e1e1e] p-4 rounded border border-gray-600 flex flex-col gap-2 min-h-[180px]">
              <div className="text-xs text-gray-500 uppercase font-bold flex items-center gap-2 border-b border-gray-700 pb-2">
                  <Recycle size={14} /> Allocator Free List (Fastbin)
              </div>
              
              <div className="flex flex-col gap-2 mt-2">
                  {binList.length === 0 && (
                      <div className="text-slate-600 text-xs italic text-center py-4">Bin is empty</div>
                  )}
                  {binList.map((addr, idx) => (
                      <div key={idx} className="flex items-center gap-2 animate-in slide-in-from-left duration-300">
                          <div className="w-6 text-slate-500 text-xs text-right">#{idx}</div>
                          <div className="bg-slate-700 text-blue-300 font-mono text-xs px-2 py-1 rounded border border-slate-600 flex-1 flex justify-between items-center">
                              <span>{addr}</span>
                              {chunkState === 'double_free' && idx === 0 && binList.length > 1 && binList[0] === binList[1] && (
                                  <AlertTriangle size={12} className="text-red-500" />
                              )}
                          </div>
                      </div>
                  ))}
                  {chunkState === 'double_free' && (
                      <div className="text-[10px] text-red-400 mt-1 text-center font-bold">
                          Circular Reference Detected!
                      </div>
                  )}
              </div>
          </div>

          {/* Connection Arrows */}
          <div className="flex flex-col justify-center items-center py-10 opacity-30">
              <ArrowRight size={24} className="text-slate-400" />
          </div>

          {/* Heap Chunk Visualization */}
          <div className="flex-1 flex flex-col items-center gap-4 min-h-[180px]">
              <div className="relative group">
                  <div className={`w-32 h-24 border-2 rounded-lg flex flex-col items-center justify-center transition-all duration-500 
                      ${chunkState === 'alloc' ? 'bg-blue-900/20 border-blue-500' : ''}
                      ${chunkState === 'free' ? 'bg-slate-800 border-slate-600 border-dashed opacity-70' : ''}
                      ${chunkState === 'double_free' ? 'bg-red-900/20 border-red-500 ring-4 ring-red-500/20' : ''}
                      ${chunkState === 'overlap' ? 'bg-purple-900/30 border-purple-500' : ''}
                  `}>
                      <div className="absolute -top-3 bg-slate-900 px-2 text-[10px] text-slate-400 font-mono">0x804A008</div>
                      
                      {chunkState === 'free' || chunkState === 'double_free' ? (
                          <>
                            <Recycle className="text-slate-500 mb-1" size={24} />
                            <span className="text-xs text-slate-500 font-bold">FREED</span>
                          </>
                      ) : (
                          <>
                            <Box className={chunkState === 'overlap' ? 'text-purple-400' : 'text-blue-400'} size={24} />
                            <span className="text-xs text-slate-300 font-bold mt-1">DATA</span>
                          </>
                      )}
                  </div>

                  {/* Pointers pointing to this chunk */}
                  <div className="absolute -left-20 top-0 flex flex-col gap-2">
                       {/* Main Ptr */}
                       <div className={`transition-all duration-300 flex items-center gap-1 justify-end
                           ${step.dfPtr1 ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4'}
                       `}>
                           <span className="font-mono text-xs text-blue-300">ptr</span>
                           <div className="w-8 h-[1px] bg-blue-500"></div>
                       </div>
                  </div>

                  {/* Overlap Pointers */}
                  <div className="absolute -right-20 top-0 flex flex-col gap-4 pt-2">
                       <div className={`transition-all duration-300 flex items-center gap-1
                           ${step.dfPtr2 ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-4'}
                       `}>
                           <div className="w-8 h-[1px] bg-purple-500"></div>
                           <span className="font-mono text-xs text-purple-300">p1</span>
                       </div>
                        <div className={`transition-all duration-300 flex items-center gap-1
                           ${step.dfPtr3 ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-4'}
                       `}>
                           <div className="w-8 h-[1px] bg-red-500"></div>
                           <span className="font-mono text-xs text-red-300">p2</span>
                       </div>
                  </div>
              </div>
              
              <div className="text-center">
                  {chunkState === 'overlap' && (
                       <div className="text-xs text-red-300 bg-red-900/20 px-2 py-1 rounded border border-red-500/50">
                           CRITICAL: p1 and p2 own the same memory!
                       </div>
                  )}
              </div>
          </div>
      </div>
      
      <div className="text-xs text-slate-400 bg-slate-900/50 p-3 rounded text-center">
          Allocator logic: <span className="font-mono text-slate-300">malloc()</span> returns the address at the top of the Free List. <span className="font-mono text-slate-300">free()</span> pushes an address onto the Free List.
      </div>

    </div>
  );
};