
import React from 'react';
import { AnimationStep } from '../types';
import { Shield, Server, ArrowRight, Search, FileCode, CheckCircle, XCircle, AlertTriangle, Filter } from 'lucide-react';

interface WafVisualizerProps {
  step: AnimationStep;
}

export const WafVisualizer: React.FC<WafVisualizerProps> = ({ step }) => {
  const wafStep = step.wafStep || 'request';
  
  return (
    <div className="flex flex-col gap-6 w-full max-w-5xl mx-auto p-4">
        
        {/* 1. Traffic Flow Diagram */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
            
            {/* Input Traffic */}
            <div className="flex flex-col gap-3">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider text-center">Incoming Traffic</span>
                <div className={`p-4 rounded-xl border-2 transition-all duration-500 bg-slate-900 ${wafStep === 'request' ? 'border-blue-500 shadow-lg' : 'border-slate-700 opacity-60'}`}>
                    <div className="bg-black p-2 rounded text-[10px] font-mono text-green-400 break-all border border-slate-800">
                        GET /product?id=<span className="text-red-400 font-bold">1%27%20OR%201%3D1</span>
                    </div>
                </div>
            </div>

            {/* WAF ENGINE */}
            <div className="flex flex-col gap-3 relative">
                 <span className="text-xs font-bold text-slate-500 uppercase tracking-wider text-center">WAF Inspection Engine</span>
                 <div className={`p-6 rounded-2xl border-2 transition-all duration-500 relative z-10 
                     ${['normalization', 'matching'].includes(wafStep) ? 'border-purple-500 bg-purple-900/10 scale-105 shadow-2xl' : 
                       wafStep === 'block' ? 'border-red-500 bg-red-900/10' : 
                       wafStep === 'pass' ? 'border-green-500 bg-green-900/10' : 'border-slate-700 bg-slate-800/50'}
                 `}>
                     <div className="flex flex-col gap-4">
                         {/* Normalization Layer */}
                         <div className={`p-2 rounded border text-[10px] flex items-center justify-between transition-all ${wafStep === 'normalization' ? 'bg-blue-900/40 border-blue-400 text-blue-100' : 'bg-slate-900 border-slate-700 text-slate-500'}`}>
                             <div className="flex items-center gap-2">
                                <Filter size={12}/> <span>URL Decoding / Normalization</span>
                             </div>
                             {wafStep === 'normalization' && <span className="font-mono text-blue-400">1' OR 1=1</span>}
                         </div>

                         {/* Pattern Matching Layer */}
                         <div className={`p-2 rounded border text-[10px] flex flex-col gap-2 transition-all ${wafStep === 'matching' ? 'bg-purple-900/40 border-purple-400 text-purple-100' : 'bg-slate-900 border-slate-700 text-slate-500'}`}>
                             <div className="flex items-center gap-2">
                                <Search size={12}/> <span>Regex Rule Matching</span>
                             </div>
                             {wafStep === 'matching' && (
                                 <div className="bg-black/50 p-1 rounded font-mono text-red-400 border border-red-900/50">
                                     Matched: {step.wafRuleMatch}
                                 </div>
                             )}
                         </div>
                     </div>
                     
                     <Shield size={32} className={`absolute -top-4 -right-4 transition-colors ${['normalization', 'matching'].includes(wafStep) ? 'text-purple-400' : wafStep === 'block' ? 'text-red-500' : wafStep === 'pass' ? 'text-green-500' : 'text-slate-600'}`} />
                 </div>
                 
                 {/* Connection Lines */}
                 <div className="absolute left-[-20px] top-1/2 -translate-y-1/2 hidden md:block">
                    <ArrowRight size={20} className={wafStep === 'request' ? 'text-blue-500 animate-pulse' : 'text-slate-700'} />
                 </div>
            </div>

            {/* Decision Result */}
            <div className="flex flex-col gap-3">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider text-center">Decision</span>
                <div className={`p-6 rounded-xl border-2 transition-all duration-500 flex flex-col items-center justify-center min-h-[100px]
                    ${wafStep === 'block' ? 'border-red-500 bg-red-900/20 shadow-[0_0_20px_rgba(239,68,68,0.2)]' : 
                      wafStep === 'pass' ? 'border-green-500 bg-green-900/20' : 'border-slate-700 bg-slate-900/30'}
                `}>
                    {wafStep === 'block' && (
                        <div className="flex flex-col items-center gap-2 animate-in zoom-in">
                            <XCircle size={32} className="text-red-500" />
                            <span className="text-xs font-bold text-red-400">403 Forbidden</span>
                        </div>
                    )}
                    {wafStep === 'pass' && (
                        <div className="flex flex-col items-center gap-2 animate-in zoom-in">
                            <CheckCircle size={32} className="text-green-500" />
                            <span className="text-xs font-bold text-green-400">Request Proxied</span>
                        </div>
                    )}
                    {['request', 'normalization', 'matching'].includes(wafStep) && (
                        <span className="text-xs text-slate-600 italic">Processing...</span>
                    )}
                </div>
            </div>

        </div>

        {/* 2. Technical Stack & Stack Analysis */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-6">
                <h3 className="text-sm font-bold text-slate-200 border-b border-slate-700 pb-2 mb-4 flex items-center gap-2">
                    <FileCode size={16} className="text-blue-400" /> WAF 核心技术栈
                </h3>
                <div className="grid grid-cols-2 gap-4">
                    <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-bold text-slate-500 uppercase">高性能网关</span>
                        <span className="text-xs text-slate-300 font-mono">Nginx / OpenResty / Envoy</span>
                    </div>
                    <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-bold text-slate-500 uppercase">检测引擎</span>
                        <span className="text-xs text-slate-300 font-mono">Lua (ModSecurity) / Rust</span>
                    </div>
                    <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-bold text-slate-500 uppercase">情报源</span>
                        <span className="text-xs text-slate-300 font-mono">IP 灰名单 / 威胁情报 API</span>
                    </div>
                    <div className="flex flex-col gap-1">
                        <span className="text-[10px] font-bold text-slate-500 uppercase">语义分析</span>
                        <span className="text-xs text-slate-300 font-mono">LibInjection (SQLi 分析)</span>
                    </div>
                </div>
            </div>

            <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-6">
                <h3 className="text-sm font-bold text-slate-200 border-b border-slate-700 pb-2 mb-4 flex items-center gap-2">
                    <Shield size={16} className="text-green-400" /> WAF 的局限性与挑战
                </h3>
                <ul className="text-xs text-slate-400 space-y-2">
                    <li className="flex items-start gap-2">
                        <AlertTriangle size={12} className="text-yellow-500 mt-0.5 shrink-0" />
                        <span><strong>编码绕过:</strong> 攻击者利用多重 URL 编码、Unicode 或特殊字符截断尝试躲避正则。</span>
                    </li>
                    <li className="flex items-start gap-2">
                        <AlertTriangle size={12} className="text-yellow-500 mt-0.5 shrink-0" />
                        <span><strong>业务误杀:</strong> 过于严苛的规则可能拦截正常的 JSON payload 或 API 调用。</span>
                    </li>
                    <li className="flex items-start gap-2">
                        <AlertTriangle size={12} className="text-yellow-500 mt-0.5 shrink-0" />
                        <span><strong>检测性能:</strong> 复杂的递归规则和深层包分析会增加 HTTP 请求的延迟。</span>
                    </li>
                </ul>
            </div>
        </div>

    </div>
  );
};
