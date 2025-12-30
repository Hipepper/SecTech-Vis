
import React from 'react';
import { AnimationStep } from '../types';
import { Box, Key, ArrowDown, Grid, Shuffle, Search, Cpu, RefreshCw, XCircle } from 'lucide-react';

interface AesVisualizerProps {
  step: AnimationStep;
}

export const AesVisualizer: React.FC<AesVisualizerProps> = ({ step }) => {
  const currentState = step.aesState || 'input';
  const operation = step.aesOperation || 'none';
  const matrix = step.aesMatrix || Array(16).fill("00");
  const roundKey = step.aesRoundKey || Array(16).fill("00");
  const highlight = step.aesHighlight || 'none';

  // Helper to render the 4x4 State Matrix
  const renderMatrix = (data: string[], title: string, isKey = false) => (
    <div className={`flex flex-col gap-2 p-3 rounded-lg border transition-all duration-500
        ${isKey ? 'bg-yellow-900/10 border-yellow-500/50' : 'bg-blue-900/10 border-blue-500/50'}
    `}>
        <div className="flex justify-between items-center text-xs font-bold uppercase tracking-wider text-slate-400">
            <span>{title}</span>
            {isKey ? <Key size={12}/> : <Grid size={12}/>}
        </div>
        <div className="grid grid-cols-4 gap-1">
            {data.map((byte, idx) => (
                <div key={idx} className={`
                    w-8 h-8 flex items-center justify-center text-xs font-mono rounded border
                    ${isKey ? 'border-yellow-700 bg-yellow-900/20 text-yellow-200' : 'border-blue-700 bg-blue-900/20 text-blue-200'}
                    ${highlight === 'sbox' && !isKey ? 'animate-pulse bg-purple-500/40 border-purple-400 text-white' : ''}
                    ${highlight === 'row' && !isKey && Math.floor(idx / 4) === 1 ? 'translate-x-2 bg-green-500/20' : ''}
                    ${highlight === 'col' && !isKey && (idx % 4) === 0 ? 'bg-red-500/20' : ''}
                `}>
                    {byte}
                </div>
            ))}
        </div>
    </div>
  );

  return (
    <div className="flex flex-col gap-6 w-full max-w-5xl mx-auto p-4">
        
        {/* Header Logic Flow */}
        <div className="flex items-center justify-center gap-2 text-xs font-bold text-slate-500 uppercase tracking-widest mb-4 flex-wrap">
            <span className={operation === 'expand' ? 'text-white bg-slate-700 px-2 rounded' : ''}>KeyExp</span>
            <ArrowDown size={12} className="-rotate-90"/>
            <span className={operation === 'subbytes' ? 'text-purple-400 bg-purple-900/20 px-2 rounded' : ''}>SubBytes</span>
            <ArrowDown size={12} className="-rotate-90"/>
            <span className={operation === 'shiftrows' ? 'text-green-400 bg-green-900/20 px-2 rounded' : ''}>ShiftRows</span>
            <ArrowDown size={12} className="-rotate-90"/>
            <span className={operation === 'mixcolumns' ? 'text-red-400 bg-red-900/20 px-2 rounded' : ''}>MixColumns</span>
            <ArrowDown size={12} className="-rotate-90"/>
            <span className={operation === 'addroundkey' ? 'text-yellow-400 bg-yellow-900/20 px-2 rounded' : ''}>AddKey</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
            
            {/* LEFT: Algorithm State */}
            <div className="bg-slate-900 border border-slate-700 rounded-xl p-6 shadow-xl flex flex-col items-center gap-6 relative min-h-[400px]">
                <div className="absolute top-2 left-3 text-xs font-bold text-slate-500 flex items-center gap-2">
                    <RefreshCw size={12} className={step.aesRound > 0 ? "animate-spin-slow" : ""} />
                    AES-128 轮次 (Round): {step.aesRound}
                </div>
                
                {/* Key Expansion View */}
                {currentState === 'key_expansion' && (
                    <div className="flex flex-col items-center gap-4 animate-in fade-in zoom-in">
                        <div className="text-sm font-bold text-yellow-400 mb-2">Key Schedule (密钥编排)</div>
                        <div className="flex gap-2">
                            <div className="bg-slate-800 p-2 rounded border border-slate-600 text-xs">Master Key</div>
                            <ArrowDown className="-rotate-90 text-slate-500"/>
                            <div className="bg-slate-800 p-2 rounded border border-slate-600 text-xs">Rcon Ops</div>
                            <ArrowDown className="-rotate-90 text-slate-500"/>
                            <div className="bg-yellow-900/30 p-2 rounded border border-yellow-600 text-xs text-yellow-300 font-bold">11 Round Keys</div>
                        </div>
                        {renderMatrix(roundKey, "Initial Round Key (K0)", true)}
                    </div>
                )}

                {currentState !== 'key_expansion' && (
                    <>
                        {/* State Matrix */}
                        {renderMatrix(matrix, "State Matrix (4x4)")}

                        {/* Operation Visualizer */}
                        <div className="h-16 w-full flex items-center justify-center">
                            {operation === 'subbytes' && (
                                <div className="flex items-center gap-2 text-purple-400 animate-in fade-in zoom-in">
                                    <Shuffle size={24} />
                                    <div className="flex flex-col">
                                        <span className="font-bold text-sm">字节替换 (S-Box)</span>
                                        <span className="text-[10px] text-slate-400">非线性替换 (查表)</span>
                                    </div>
                                </div>
                            )}
                            {operation === 'shiftrows' && (
                                <div className="flex items-center gap-2 text-green-400 animate-in fade-in slide-in-from-left">
                                    <ArrowDown size={24} className="-rotate-90" />
                                    <div className="flex flex-col">
                                        <span className="font-bold text-sm">行移位 (ShiftRows)</span>
                                        <span className="text-[10px] text-slate-400">循环左移</span>
                                    </div>
                                </div>
                            )}
                            {operation === 'mixcolumns' && (
                                <div className="flex items-center gap-2 text-red-400 animate-in fade-in zoom-in">
                                    <Grid size={24} />
                                    <div className="flex flex-col">
                                        <span className="font-bold text-sm">列混淆 (MixColumns)</span>
                                        <span className="text-[10px] text-slate-400">GF(2^8) 矩阵乘法</span>
                                    </div>
                                </div>
                            )}
                            {operation === 'addroundkey' && (
                                <div className="flex items-center gap-2 text-yellow-400 animate-in fade-in">
                                    <Key size={24} />
                                    <div className="flex flex-col">
                                        <span className="font-bold text-sm">轮密钥加 (XOR)</span>
                                        <span className="text-[10px] text-slate-400">State ^ RoundKey[{step.aesRound}]</span>
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Round Key (Shown during AddRoundKey) */}
                        <div className={`transition-opacity duration-500 ${operation === 'addroundkey' ? 'opacity-100' : 'opacity-30 blur-sm scale-90'}`}>
                            {renderMatrix(roundKey, `Round Key (K${step.aesRound})`, true)}
                        </div>
                    </>
                )}

            </div>

            {/* RIGHT: Reverse Engineering Context (Chinese) */}
            <div className="flex flex-col gap-4">
                
                {/* Reverser's View */}
                <div className="bg-[#1e1e1e] rounded-xl border border-slate-600 p-4 relative overflow-hidden">
                    <div className="flex items-center gap-2 text-slate-200 font-bold border-b border-slate-700 pb-2 mb-2">
                        <Search size={18} className="text-orange-400" />
                        逆向分析特征 (Signatures)
                    </div>
                    
                    <div className="flex flex-col gap-3 text-sm text-slate-400">
                        <p>如何在没有源码的情况下识别 AES 算法？</p>
                        
                        <div className={`p-3 rounded border transition-colors duration-500 ${operation === 'subbytes' ? 'bg-purple-900/20 border-purple-500 text-purple-200' : 'bg-slate-800 border-slate-700'}`}>
                            <span className="font-bold text-xs uppercase block mb-1">1. S-Box 常量特征</span>
                            <div className="font-mono text-xs break-all opacity-80">
                                0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F...
                            </div>
                            <div className="text-[10px] mt-1 text-slate-500">
                                在二进制中搜索这 256 字节的数组，是识别 AES 最快的方法。
                            </div>
                        </div>

                        <div className={`p-3 rounded border transition-colors duration-500 ${operation === 'mixcolumns' ? 'bg-red-900/20 border-red-500 text-red-200' : 'bg-slate-800 border-slate-700'}`}>
                            <span className="font-bold text-xs uppercase block mb-1">2. 列混淆常量 (MixColumns)</span>
                            <div className="font-mono text-xs opacity-80">
                                乘法常量: 0x02, 0x03, 0x01, 0x01
                            </div>
                        </div>

                        <div className={`p-3 rounded border transition-colors duration-500 ${currentState === 'round_final' ? 'bg-orange-900/20 border-orange-500 text-orange-200' : 'bg-slate-800 border-slate-700'}`}>
                            <span className="font-bold text-xs uppercase block mb-1">3. 最终轮特征</span>
                            <div className="flex items-center gap-2 text-[10px]">
                                <XCircle size={14} className="text-red-500" /> 
                                <span>缺少 MixColumns 步骤</span>
                            </div>
                            <div className="text-[10px] mt-1 text-slate-500">
                                如果循环结束后有一次单独的 SubBytes + ShiftRows + AddKey，这通常是 AES 的最后一轮。
                            </div>
                        </div>
                    </div>
                </div>

                {/* Assembly Snippet Placeholder */}
                <div className="bg-black p-3 rounded border border-slate-700 font-mono text-[10px] text-green-400 opacity-80">
                    <div className="text-slate-500 mb-1">; 典型的 AES 汇编模式 (AES-NI)</div>
                    <div>pxor       xmm0, xmm1      ; Initial AddRoundKey</div>
                    <div>aesenc     xmm0, xmm2      ; Round 1</div>
                    <div>aesenc     xmm0, xmm3      ; Round 2</div>
                    <div>...</div>
                    <div>aesenclast xmm0, xmm11     ; Final Round</div>
                </div>

            </div>

        </div>
    </div>
  );
};
