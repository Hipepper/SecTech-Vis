
import React from 'react';
import { AnimationStep } from '../types';
import { Globe, Search, Server, Zap, Database, ArrowRight, ShieldCheck, Activity, Cpu, Network } from 'lucide-react';

interface NetworkMappingVisualizerProps {
  step: AnimationStep;
}

export const NetworkMappingVisualizer: React.FC<NetworkMappingVisualizerProps> = ({ step }) => {
  const nmStep = step.nmStep || 'discovery';
  const targets = step.nmTargets || [];
  
  return (
    <div className="flex flex-col gap-6 w-full max-w-5xl mx-auto p-4">
        
        {/* 1. Distributed Scanner Nodes & Public Internet */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            
            {/* Left: The Mapping Process */}
            <div className="flex flex-col gap-4">
                <div className="flex items-center gap-2 text-blue-400 font-bold uppercase tracking-wider text-sm">
                    <Zap size={18} className="animate-pulse" /> 测绘探测流程 (Discovery Process)
                </div>
                
                <div className="bg-slate-900 border border-slate-700 rounded-xl p-6 shadow-xl relative overflow-hidden">
                    <div className="grid grid-cols-4 gap-4 mb-8">
                        {targets.map((t, i) => (
                            <div key={i} className={`
                                p-2 rounded border flex flex-col items-center gap-1 transition-all duration-500
                                ${t.status === 'identified' ? 'bg-green-900/20 border-green-500 shadow-[0_0_10px_rgba(34,197,94,0.3)] scale-105' : 
                                  t.status === 'scanned' ? 'bg-blue-900/20 border-blue-400 animate-pulse' : 'bg-slate-800 border-slate-700'}
                            `}>
                                <Server size={16} className={t.status === 'idle' ? 'text-slate-600' : 'text-blue-400'} />
                                <span className="text-[8px] font-mono text-slate-400">{t.ip}</span>
                                {t.app && <span className="text-[8px] font-bold text-green-400 uppercase truncate w-full text-center">{t.app}</span>}
                            </div>
                        ))}
                    </div>

                    {/* Scanner Node Visualization */}
                    <div className="flex justify-center items-center gap-4 border-t border-slate-800 pt-6">
                        <div className={`p-4 rounded-full border-2 transition-all duration-300 ${step.nmScannerActive ? 'bg-blue-900/40 border-blue-500 shadow-lg scale-110' : 'bg-slate-800 border-slate-700 opacity-50'}`}>
                            <Cpu size={32} className={step.nmScannerActive ? 'text-blue-400 animate-spin-slow' : 'text-slate-500'} />
                        </div>
                        <div className="flex flex-col">
                            <span className="text-xs font-bold text-slate-200">分布式探测节点 (Scanner Node)</span>
                            <span className="text-[10px] text-slate-500">ZMap / Masscan / Nmap Optimized</span>
                        </div>
                    </div>

                    {/* Laser probes */}
                    {step.nmScannerActive && nmStep !== 'query' && (
                        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none w-full h-full">
                            <div className="w-full h-full animate-pulse bg-blue-500/5 rounded-full blur-3xl"></div>
                        </div>
                    )}
                </div>
            </div>

            {/* Right: Platform Architecture (FOFA Style) */}
            <div className="flex flex-col gap-4">
                <div className="flex items-center gap-2 text-purple-400 font-bold uppercase tracking-wider text-sm">
                    <Database size={18} /> 测绘平台架构 (Platform Architecture)
                </div>
                
                <div className="bg-[#1e1e1e] border-2 border-slate-700 rounded-xl p-6 flex flex-col gap-4 shadow-2xl">
                    
                    {/* Layer 1: Data Sink */}
                    <div className={`p-3 rounded border transition-all duration-500 ${['indexing', 'query'].includes(nmStep) ? 'bg-purple-900/20 border-purple-500 text-purple-200' : 'bg-slate-800 border-slate-700 opacity-60'}`}>
                         <div className="flex items-center gap-2 mb-1">
                             <Activity size={14} />
                             <span className="text-xs font-bold">数据清洗与指纹匹配 (Fingerprinting)</span>
                         </div>
                         <p className="text-[10px] text-slate-400">正则库提取: Server, Header, Cert, Favicon-Hash</p>
                    </div>

                    {/* Layer 2: Storage */}
                    <div className={`p-3 rounded border transition-all duration-500 ${['indexing', 'query'].includes(nmStep) ? 'bg-blue-900/20 border-blue-500 text-blue-200' : 'bg-slate-800 border-slate-700 opacity-60'}`}>
                         <div className="flex items-center gap-2 mb-1">
                             <Database size={14} />
                             <span className="text-xs font-bold">海量数据索引 (Elasticsearch / ClickHouse)</span>
                         </div>
                         <p className="text-[10px] text-slate-400">亿级资产秒级检索, 支持 DSL 语法查询</p>
                    </div>

                    {/* Layer 3: Query Interface */}
                    <div className={`p-3 rounded border-2 transition-all duration-500 ${nmStep === 'query' ? 'bg-green-900/20 border-green-500 text-green-200 ring-2 ring-green-500/50' : 'bg-slate-800 border-slate-700 opacity-60'}`}>
                         <div className="flex items-center gap-2 mb-2">
                             <Search size={14} />
                             <span className="text-xs font-bold">搜索界面 (FOFA Query Interface)</span>
                         </div>
                         <div className="bg-black/40 p-2 rounded border border-slate-700 font-mono text-[10px] text-green-400 flex items-center justify-between">
                            <span>{step.nmQuery || 'app="ThinkPHP" && country="CN"'}</span>
                            {nmStep === 'query' && <Zap size={12} className="animate-pulse" />}
                         </div>
                    </div>
                </div>
            </div>
        </div>

        {/* 2. Technical Summary (Chinese) */}
        <div className="bg-slate-900 border border-slate-700 rounded-xl p-6 grid grid-cols-1 md:grid-cols-2 gap-8 items-start">
            <div className="flex flex-col gap-3">
                <h3 className="text-sm font-bold text-slate-200 border-b border-slate-700 pb-2 flex items-center gap-2">
                    <Globe size={16} className="text-blue-400" /> 网络测绘核心技术
                </h3>
                <ul className="space-y-3">
                    <li className="flex items-start gap-3">
                        <div className="bg-blue-500/20 p-1.5 rounded-lg text-blue-400 mt-0.5"><Activity size={12}/></div>
                        <div className="flex flex-col">
                            <span className="text-xs font-bold text-slate-300">高速探测引擎</span>
                            <p className="text-[10px] text-slate-500 leading-relaxed">利用无状态扫描技术（如 Masscan）在几小时内完成全球 IPv4 空间的全端口存活探测。</p>
                        </div>
                    </li>
                    <li className="flex items-start gap-3">
                        <div className="bg-purple-500/20 p-1.5 rounded-lg text-purple-400 mt-0.5"><Network size={12}/></div>
                        <div className="flex flex-col">
                            <span className="text-xs font-bold text-slate-300">多维指纹识别</span>
                            <p className="text-[10px] text-slate-500 leading-relaxed">通过解析 HTTP 报文、TLS 证书、JARM 签名等特征，将 IP 转化为带有“标签”的资产。</p>
                        </div>
                    </li>
                </ul>
            </div>

            <div className="flex flex-col gap-3">
                <h3 className="text-sm font-bold text-slate-200 border-b border-slate-700 pb-2 flex items-center gap-2">
                    <ShieldCheck size={16} className="text-green-400" /> 防御者挑战与意义
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed italic">
                    "知彼知己，百战不殆。"
                </p>
                <div className="bg-slate-800/50 p-3 rounded border border-slate-700 text-[11px] text-slate-400 space-y-2">
                    <p>● <span className="text-yellow-400">暴露面分析：</span> 企业通过测绘平台发现影子资产和遗忘在公网的测试环境。</p>
                    <p>● <span className="text-red-400">威胁预警：</span> 当新 0day 爆发时，安全人员可利用测绘数据迅速评估全球/全网受影响规模。</p>
                    <p>● <span className="text-blue-400">攻击面发现：</span> 攻击者利用测绘快速定位特定版本的漏洞目标。</p>
                </div>
            </div>
        </div>

    </div>
  );
};
