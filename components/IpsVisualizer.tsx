
import React from 'react';
import { AnimationStep } from '../types';
import { ShieldAlert, Cpu, Network, ArrowRight, AlertCircle, XOctagon, Database, Activity, Package, Layout, Globe, Shield, Zap, Search } from 'lucide-react';

interface IpsVisualizerProps {
  step: AnimationStep;
}

export const IpsVisualizer: React.FC<IpsVisualizerProps> = ({ step }) => {
  const ipsStep = step.ipsStep || 'capture';
  
  return (
    <div className="flex flex-col gap-6 w-full max-w-5xl mx-auto p-4">
        
        {/* 1. IPS Inline Pipeline */}
        <div className="relative bg-slate-900 border border-slate-700 rounded-2xl p-8 overflow-hidden min-h-[350px] flex flex-col justify-center shadow-2xl">
            
            {/* Background Grid */}
            <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/grid-me.png')] opacity-10"></div>

            <div className="flex items-center justify-between relative z-10 px-4">
                
                {/* INBOUND PACKETS */}
                <div className="flex flex-col items-center gap-4 w-1/4">
                    <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Inbound Traffic</div>
                    <div className="flex flex-col gap-2">
                        {[0, 1, 2].map(i => (
                            <div key={i} className={`w-12 h-8 rounded border flex items-center justify-center text-[10px] font-mono transition-all duration-1000 
                                ${ipsStep === 'capture' ? 'bg-blue-600 border-blue-400 translate-x-4' : 'bg-slate-800 border-slate-600 opacity-30'}
                            `}>
                                <Package size={14} className="text-blue-100" />
                            </div>
                        ))}
                    </div>
                    <ArrowRight className={`text-blue-500 transition-all ${ipsStep === 'capture' ? 'opacity-100' : 'opacity-0'}`} />
                </div>

                {/* IPS DEVICE (INLINE) */}
                <div className={`w-2/5 p-6 rounded-3xl border-4 transition-all duration-500 relative flex flex-col items-center gap-4
                    ${ipsStep === 'dpi' ? 'border-purple-500 bg-purple-900/20 scale-105 shadow-[0_0_30px_rgba(168,85,247,0.3)]' : 
                      ipsStep === 'alert' ? 'border-yellow-500 bg-yellow-900/20' : 
                      ipsStep === 'drop' ? 'border-red-600 bg-red-900/20' : 'border-slate-600 bg-slate-800'}
                `}>
                    <div className="absolute -top-4 bg-slate-900 px-3 py-1 rounded-full border border-inherit text-xs font-bold text-slate-300">
                        Intrusion Prevention System (IPS)
                    </div>

                    <div className="flex items-center gap-4 w-full">
                        <div className="p-3 bg-black/40 rounded-xl border border-slate-700 flex-1">
                            <div className="text-[9px] text-slate-500 uppercase font-bold mb-1">DPI Analysis</div>
                            <div className="font-mono text-[10px] text-slate-300 leading-tight">
                                {ipsStep === 'dpi' ? (
                                    <div className="animate-pulse">
                                        Layer 3: IP (OK)<br/>
                                        Layer 4: TCP (OK)<br/>
                                        Layer 7: Inspection...
                                    </div>
                                ) : ipsStep === 'alert' || ipsStep === 'drop' ? (
                                    <div className="text-red-400">
                                        MATCH: SID 10004<br/>
                                        RCE ATTEMPT: /etc/passwd
                                    </div>
                                ) : 'Waiting...'}
                            </div>
                        </div>
                        <Cpu size={40} className={ipsStep === 'dpi' ? 'text-purple-400 animate-spin-slow' : 'text-slate-600'} />
                    </div>

                    {ipsStep === 'alert' && (
                        <div className="absolute -right-8 top-1/2 -translate-y-1/2 bg-yellow-600 text-white p-2 rounded-full animate-bounce shadow-lg">
                            <AlertCircle size={20} />
                        </div>
                    )}
                </div>

                {/* OUTBOUND / DROP */}
                <div className="w-1/4 flex flex-col items-center gap-4">
                    <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Decision</div>
                    
                    {ipsStep === 'drop' && (
                        <div className="flex flex-col items-center gap-2 animate-in zoom-in duration-300">
                            <div className="p-4 bg-red-900/40 rounded-full border-2 border-red-500 text-red-500">
                                <XOctagon size={32} />
                            </div>
                            <span className="text-[10px] font-bold text-red-400 uppercase">Packet Dropped</span>
                        </div>
                    )}

                    {ipsStep === 'allow' && (
                        <div className="flex flex-col items-center gap-2 animate-in slide-in-from-left duration-500">
                            <div className="p-4 bg-green-900/40 rounded-full border-2 border-green-500 text-green-500">
                                <ArrowRight size={32} />
                            </div>
                            <span className="text-[10px] font-bold text-green-400 uppercase">Traffic Passed</span>
                        </div>
                    )}
                </div>

            </div>
        </div>

        {/* 2. Knowledge Alignment Module (Bilingual) */}
        <div className="bg-slate-900/50 border border-slate-700 rounded-xl p-6 flex flex-col gap-6 shadow-xl">
            <div className="flex items-center gap-2 border-b border-slate-700 pb-3">
                <Search size={20} className="text-blue-400" />
                <h3 className="text-lg font-bold text-slate-100">知识对齐: 安全边界深度解析 (Knowledge Alignment)</h3>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                
                {/* IPS vs WAF */}
                <div className="flex flex-col gap-4">
                    <h4 className="text-sm font-bold text-purple-400 flex items-center gap-2 uppercase tracking-wider">
                        <Zap size={16} /> IPS vs WAF: 职责区别
                    </h4>
                    <div className="overflow-hidden rounded-lg border border-slate-800 bg-black/30">
                        <table className="w-full text-[11px] text-left border-collapse">
                            <thead className="bg-slate-800 text-slate-300">
                                <tr>
                                    <th className="p-2 border-b border-slate-700">维度</th>
                                    <th className="p-2 border-b border-slate-700">IPS</th>
                                    <th className="p-2 border-b border-slate-700">WAF</th>
                                </tr>
                            </thead>
                            <tbody className="text-slate-400">
                                <tr className="border-b border-slate-800">
                                    <td className="p-2 font-bold text-slate-300 bg-slate-800/10">协议层级</td>
                                    <td className="p-2">L3 - L7 (全流量)</td>
                                    <td className="p-2">L7 (仅 HTTP/Web)</td>
                                </tr>
                                <tr className="border-b border-slate-800">
                                    <td className="p-2 font-bold text-slate-300 bg-slate-800/10">防护重心</td>
                                    <td className="p-2">系统漏洞 (RCE, DOS, 溢出)</td>
                                    <td className="p-2">应用逻辑 (SQLi, XSS, 业务绕过)</td>
                                </tr>
                                <tr>
                                    <td className="p-2 font-bold text-slate-300 bg-slate-800/10">检测深度</td>
                                    <td className="p-2">报文特征、包序列分析</td>
                                    <td className="p-2">参数规范化、语义分析</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    <p className="text-[10px] text-slate-500 italic leading-relaxed">
                        IPS 像是一位全能警察，检查所有交通工具（协议）；WAF 则是专门检查“Web 外卖车”的质检员。
                    </p>
                </div>

                {/* IPS & Firewall */}
                <div className="flex flex-col gap-4">
                    <h4 className="text-sm font-bold text-blue-400 flex items-center gap-2 uppercase tracking-wider">
                        <Shield size={16} /> IPS & 防火墙 (Firewall): 协作关系
                    </h4>
                    <div className="flex flex-col gap-3">
                        <div className="p-3 bg-slate-800/40 rounded border border-slate-700 flex gap-3">
                            <div className="shrink-0"><div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center font-bold text-xs">FW</div></div>
                            <div className="flex flex-col">
                                <span className="text-xs font-bold text-slate-200">防火墙: “守门人” (Gatekeeper)</span>
                                <p className="text-[10px] text-slate-500">基于 5 元组（IP, 端口等）决定“谁能进”。不做内容拆解。</p>
                            </div>
                        </div>
                        <div className="flex justify-center -my-1 text-slate-700"><ArrowRight size={14} className="rotate-90" /></div>
                        <div className="p-3 bg-slate-800/40 rounded border border-slate-700 flex gap-3">
                            <div className="shrink-0"><div className="w-8 h-8 rounded-full bg-purple-600 flex items-center justify-center font-bold text-xs">IPS</div></div>
                            <div className="flex flex-col">
                                <span className="text-xs font-bold text-slate-200">IPS: “安检仪” (Inspector)</span>
                                <p className="text-[10px] text-slate-500">打开包裹（报文）检查内容。发现违禁品（漏洞载荷）即销毁。</p>
                            </div>
                        </div>
                        <div className="bg-blue-900/10 border border-blue-800/50 p-2 rounded text-[11px] text-blue-300">
                            <strong>趋势:</strong> 下一代防火墙 (NGFW) 将两者融合，在一次处理流程中完成策略准入和深度检测。
                        </div>
                    </div>
                </div>

            </div>
        </div>

        {/* 3. Technical Summary (Existing) */}
        <div className="bg-slate-900 border border-slate-700 rounded-xl p-6 grid grid-cols-1 md:grid-cols-2 gap-8 items-start">
            <div className="flex flex-col gap-3">
                <h3 className="text-sm font-bold text-slate-200 border-b border-slate-700 pb-2 flex items-center gap-2">
                    <Network size={16} className="text-blue-400" /> IPS 核心架构与原理
                </h3>
                <ul className="space-y-3">
                    <li className="flex items-start gap-3">
                        <div className="bg-blue-500/20 p-1.5 rounded-lg text-blue-400 mt-0.5"><Activity size={12}/></div>
                        <div className="flex flex-col">
                            <span className="text-xs font-bold text-slate-300">深度报文检测 (DPI)</span>
                            <p className="text-[10px] text-slate-500 leading-relaxed">不同于普通防火墙只看端口/IP，IPS 会解开应用层协议（HTTP, RPC, SQL）的内容进行深度匹配。</p>
                        </div>
                    </li>
                    <li className="flex items-start gap-3">
                        <div className="bg-purple-500/20 p-1.5 rounded-lg text-purple-400 mt-0.5"><Database size={12}/></div>
                        <div className="flex flex-col">
                            <span className="text-xs font-bold text-slate-300">特征匹配 (Signatures)</span>
                            <p className="text-[10px] text-slate-500 leading-relaxed">维护一个海量的漏洞特征库（如 Snort Rules），通过 Aho-Corasick 等算法在流式数据中快速检索威胁。</p>
                        </div>
                    </li>
                </ul>
            </div>

            <div className="flex flex-col gap-3">
                <h3 className="text-sm font-bold text-slate-200 border-b border-slate-700 pb-2 flex items-center gap-2">
                    <ShieldAlert size={16} className="text-yellow-400" /> IPS vs IDS
                </h3>
                <div className="bg-black/40 p-4 rounded border border-slate-700 text-[11px] space-y-4">
                    <div className="flex gap-4">
                        <div className="flex-1">
                            <span className="text-blue-400 font-bold block mb-1">IDS (旁路监测)</span>
                            <p className="text-slate-500 leading-relaxed italic">"只报警，不拦截"。通过流量镜像部署，不影响网络性能，但无法实时阻止攻击。</p>
                        </div>
                        <div className="flex-1">
                            <span className="text-red-400 font-bold block mb-1">IPS (串联防护)</span>
                            <p className="text-slate-500 leading-relaxed italic">"发现即断开"。部署在流量必经之路，可以直接丢弃恶意包，但故障时可能影响业务。</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

    </div>
  );
};
