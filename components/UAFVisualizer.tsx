import React from 'react';
import { AnimationStep } from '../types';
import { MousePointer2, Box, Trash2, AlertTriangle } from 'lucide-react';

interface UAFVisualizerProps {
  step: AnimationStep;
}

export const UAFVisualizer: React.FC<UAFVisualizerProps> = ({ step }) => {
  
  const slotState = step.uafSlotState || 'empty';
  
  // Colors based on state
  let slotColor = 'bg-slate-800 border-slate-600';
  let slotText = 'Empty (Unallocated)';
  let slotContent = '';
  
  if (slotState === 'objA') {
      slotColor = 'bg-blue-900/40 border-blue-500 text-blue-200';
      slotText = 'Object A (Allocated)';
      slotContent = step.uafData || "SECRET";
  } else if (slotState === 'free') {
      slotColor = 'bg-slate-700/50 border-slate-500 border-dashed text-slate-400';
      slotText = 'Freed (Available)';
      slotContent = "<junk>";
  } else if (slotState === 'objB') {
      slotColor = 'bg-red-900/40 border-red-500 text-red-200';
      slotText = 'Object B (Reallocated)';
      slotContent = step.uafData || "ATTACK";
  }

  return (
    <div className="flex flex-col items-center gap-8 w-full max-w-2xl mx-auto p-6 bg-slate-800/50 rounded-xl border border-slate-700">
      
      {/* Pointers Section */}
      <div className="flex w-full justify-around">
          {/* Pointer 1 */}
          <div className="flex flex-col items-center gap-2 transition-opacity duration-300">
              <div className="text-xs font-mono text-slate-400">ptr1 (dangling)</div>
              <div className={`p-2 rounded bg-slate-700 border ${step.uafPtr1State === 'pointing' ? 'border-blue-400 text-blue-300' : 'border-slate-600 text-slate-500'}`}>
                  {step.uafPtr1State === 'pointing' ? "0x804A008" : "NULL"}
              </div>
              {step.uafPtr1State === 'pointing' && (
                  <div className="h-8 w-0.5 bg-blue-500/50"></div>
              )}
          </div>

          {/* Pointer 2 */}
          <div className="flex flex-col items-center gap-2 transition-opacity duration-300 opacity-80">
              <div className="text-xs font-mono text-slate-400">ptr2 (new)</div>
               <div className={`p-2 rounded bg-slate-700 border ${step.uafPtr2State === 'pointing' ? 'border-red-400 text-red-300' : 'border-slate-600 text-slate-500'}`}>
                  {step.uafPtr2State === 'pointing' ? "0x804A008" : "NULL"}
              </div>
              {step.uafPtr2State === 'pointing' && (
                  <div className="h-8 w-0.5 bg-red-500/50"></div>
              )}
          </div>
      </div>

      {/* Heap Memory Slot */}
      <div className="relative w-64 h-32">
          {/* Connection Lines from Pointers would theoretically go here, simplified with vertical lines above */}
          
          <div className={`w-full h-full rounded-lg border-2 flex flex-col items-center justify-center transition-all duration-500 relative ${slotColor}`}>
              {/* Header */}
              <div className="absolute top-0 w-full px-2 py-1 text-[10px] uppercase tracking-wider font-bold border-b border-inherit opacity-70 flex justify-between">
                  <span>Heap: 0x804A008</span>
                  {slotState === 'free' && <Trash2 size={12}/>}
                  {slotState !== 'free' && slotState !== 'empty' && <Box size={12}/>}
              </div>
              
              <div className="text-sm font-bold mb-1">{slotText}</div>
              <div className="font-mono text-xs opacity-80">"{slotContent}"</div>

              {/* Danger indicator */}
              {step.isCorrupted && (
                  <div className="absolute -right-24 top-1/2 -translate-y-1/2 w-20 text-xs text-red-400 font-bold animate-pulse flex flex-col items-center">
                      <AlertTriangle size={24} />
                      <span>UAF Access!</span>
                  </div>
              )}
          </div>
      </div>
      
      {/* Legend/Status */}
      <div className="text-xs text-slate-500 text-center max-w-md">
         {slotState === 'objB' && step.uafPtr1State === 'pointing' 
            ? "ptr1 still points to 0x804A008, but the memory is now owned by ptr2 (Object B). Accessing ptr1 reads Object B's data!" 
            : "The heap manager reuses freed slots for efficiency. If pointers aren't cleared, they point to new data."
         }
      </div>

    </div>
  );
};