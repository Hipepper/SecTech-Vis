import React from 'react';
import { AnimationStep, Architecture } from '../types';
import { ArrowLeft } from 'lucide-react';

interface StackVisualizerProps {
  step: AnimationStep;
  arch: Architecture;
}

export const StackVisualizer: React.FC<StackVisualizerProps> = ({ step, arch }) => {
  
  const is64Bit = arch === Architecture.X64;
  const ptrSize = is64Bit ? 8 : 4;

  // Architecture Config
  const getRegNames = (a: Architecture) => {
    switch (a) {
        case Architecture.X64: return { pc: 'RIP', fp: 'RBP', sp: 'RSP', retLabel: 'Return Address' };
        case Architecture.ARM: return { pc: 'PC', fp: 'FP (R11)', sp: 'SP', retLabel: 'LR (R14)' };
        case Architecture.MIPS: return { pc: 'PC', fp: 'FP ($fp)', sp: 'SP', retLabel: 'RA ($ra)' };
        case Architecture.X86: 
        default: return { pc: 'EIP', fp: 'EBP', sp: 'ESP', retLabel: 'Return Address' };
    }
  };
  
  const regs = getRegNames(arch);

  // Helper to convert string to Hex bytes
  const stringToHexTuple = (str: string, length: number): string => {
    let hex = "";
    for (let i = 0; i < length; i++) {
      if (i < str.length) {
        hex += str.charCodeAt(i).toString(16).toUpperCase().padStart(2, '0') + " ";
      } else {
        hex += "00 ";
      }
    }
    return hex.trim();
  };

  const getMemoryValue = (hexOrString: string | undefined, isRawHex: boolean, targetSize: number) => {
    if (!hexOrString) return Array(targetSize).fill("00").join(" ");
    
    if (isRawHex) {
        // e.g., 0x41414141. Strip 0x.
        let clean = hexOrString.replace('0x', '');
        // Pad to target size * 2 characters
        clean = clean.padStart(targetSize * 2, '0');
        // Split pairs
        const bytes = clean.match(/.{1,2}/g) || [];
        
        // Handle Endianness for display (Usually Little Endian for x86/x64/ARM-LE)
        // We will just show memory order: low addr -> high addr.
        // If value is 0x41424344 (integer), in LE it is 44 43 42 41 in memory.
        // For simplicity in this educational tool, we display human readable hex pairs.
        // Let's assume input string is already "value". We just format it.
        return bytes.join(' ');
    }
    return stringToHexTuple(hexOrString, targetSize);
  };

  const bufferFull = step.stackBufferContent || "";

  // Define Memory Rows
  let rows = [];

  // Construct stack based on architecture
  // Stack grows High -> Low.
  // Visualizer shows Top (Low Addr) -> Bottom (High Addr) ? 
  // Standard debugger view: Address increases downwards. Top of stack (ESP) is at low address.
  
  // Addresses (Mock)
  const baseAddr = is64Bit ? 0x7FFFFFFFE400 : 0x0019FF00;
  
  // We need to map the logical steps (Buffer, EBP, RET) to physical rows
  
  // 1. Buffer (8 bytes).
  // x64: 1 row (8 bytes).
  // x86/ARM/MIPS: 2 rows (4 bytes each).
  
  const bufferRows = [];
  if (is64Bit) {
      bufferRows.push({
          offset: 0, // ESP
          value: stringToHexTuple(bufferFull.slice(0, 8), 8),
          comment: `buffer "${bufferFull.slice(0, 8).replace(/\0/g, '.')}"`,
          highlight: step.highlightRegion === 'buffer',
          corrupt: false
      });
  } else {
      // 32-bit: Split buffer into two 4-byte chunks
      bufferRows.push({
          offset: 0, // ESP
          value: stringToHexTuple(bufferFull.slice(0, 4), 4),
          comment: `buffer[0..3] "${bufferFull.slice(0, 4).replace(/\0/g, '.')}"`,
          highlight: step.highlightRegion === 'buffer',
          corrupt: false
      });
      bufferRows.push({
          offset: 4, 
          value: stringToHexTuple(bufferFull.slice(4, 8), 4),
          comment: `buffer[4..7] "${bufferFull.slice(4, 8).replace(/\0/g, '.')}"`,
          highlight: step.highlightRegion === 'buffer' && bufferFull.length > 4,
          corrupt: false
      });
  }

  // 2. Saved FP (EBP/RBP)
  const fpRow = {
      offset: is64Bit ? 8 : 8,
      value: getMemoryValue(step.stackEBPContent, true, ptrSize),
      comment: `Saved ${regs.fp}`,
      highlight: step.highlightRegion === 'ebp',
      corrupt: step.isCorrupted && step.highlightRegion === 'ebp'
  };

  // 3. Return Address
  const retRow = {
      offset: is64Bit ? 16 : 12,
      value: getMemoryValue(step.stackRetContent, true, ptrSize),
      comment: regs.retLabel,
      highlight: step.highlightRegion === 'ret',
      corrupt: step.isCorrupted && step.highlightRegion === 'ret'
  };

  // Combine (Note: In standard debugger view, Low Address (ESP) is usually top)
  rows = [...bufferRows, fpRow, retRow];

  return (
    <div className="w-full max-w-2xl mx-auto font-mono text-sm bg-[#1e1e1e] border border-gray-600 rounded-sm shadow-2xl overflow-hidden">
        {/* Toolbar looking header */}
        <div className="bg-[#2d2d2d] px-2 py-1 border-b border-gray-600 flex gap-4 text-xs text-gray-300 items-center justify-between">
            <div className="flex gap-4">
                <span className="font-bold">Stack View ({arch})</span>
                <span className="text-blue-400">Thread 12A4</span>
            </div>
            <div className="text-xs text-gray-500">PtrSize: {ptrSize} bytes</div>
        </div>

        {/* Table Header */}
        <div className={`grid ${is64Bit ? 'grid-cols-[140px_1fr_1fr]' : 'grid-cols-[100px_1fr_1fr]'} bg-[#252526] text-gray-400 text-xs border-b border-gray-700`}>
            <div className="px-2 py-1 border-r border-gray-700">Address</div>
            <div className="px-2 py-1 border-r border-gray-700">Hex Value</div>
            <div className="px-2 py-1">Comment / ASCII</div>
        </div>

        {/* Table Body */}
        <div className="flex flex-col">
            {rows.map((row) => (
                <div 
                    key={row.offset} 
                    className={`
                        grid ${is64Bit ? 'grid-cols-[140px_1fr_1fr]' : 'grid-cols-[100px_1fr_1fr]'} border-b border-gray-800 transition-colors duration-300
                        ${row.corrupt ? 'bg-red-900/40 text-red-200' : ''}
                        ${row.highlight && !row.corrupt ? 'bg-blue-900/40' : ''}
                        hover:bg-[#2a2d2e]
                    `}
                >
                    <div className="px-2 py-1 text-gray-500 border-r border-gray-700 select-none">
                        {(baseAddr + row.offset).toString(16).toUpperCase().padStart(is64Bit ? 16 : 8, '0')}
                    </div>
                    <div className={`px-2 py-1 font-bold border-r border-gray-700 ${row.corrupt ? 'text-red-400' : 'text-blue-300'}`}>
                        {row.value}
                    </div>
                    <div className="px-2 py-1 text-gray-400 whitespace-nowrap overflow-hidden text-ellipsis flex items-center gap-2">
                         {row.offset === 0 && <ArrowLeft size={12} className="text-yellow-500 rotate-180" />}
                         {row.comment}
                    </div>
                </div>
            ))}
            
            {/* Context Below Stack */}
            <div className={`grid ${is64Bit ? 'grid-cols-[140px_1fr_1fr]' : 'grid-cols-[100px_1fr_1fr]'} text-gray-600 opacity-50`}>
                 <div className="px-2 py-1 border-r border-gray-800">...</div>
                 <div className="px-2 py-1 border-r border-gray-800">...</div>
                 <div className="px-2 py-1">...</div>
            </div>
        </div>

        <div className="px-2 py-1 bg-[#007acc] text-white text-xs flex justify-between">
            <span>{regs.sp}: {(baseAddr).toString(16).toUpperCase()}</span>
            <span>{regs.pc}: {step.stackInstructionPointer || "Unknown"}</span>
        </div>
    </div>
  );
};
