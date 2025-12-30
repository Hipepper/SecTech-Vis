
import React from 'react';
import { AnimationStep } from '../types';
import { Globe, Server, UserCheck, ShieldAlert, ArrowRight, Wallet, Cookie, FileCode } from 'lucide-react';

interface CsrfVisualizerProps {
  step: AnimationStep;
}

export const CsrfVisualizer: React.FC<CsrfVisualizerProps> = ({ step }) => {
  const currentState = step.csrfStep || 'login';
  const activeTab = step.csrfTab || 'bank';
  const hasCookie = step.csrfCookie;
  
  const isMaliciousTab = activeTab === 'evil';
  const showRequest = currentState === 'auto_request' || currentState === 'cookie_attach' || currentState === 'server_process';
  const showCookieAttach = currentState === 'cookie_attach' || currentState === 'server_process';
  
  return (
    <div className="flex flex-col gap-8 w-full max-w-6xl mx-auto p-4">
        
        {/* TOP: Browser View */}
        <div className="flex flex-col border-2 border-slate-600 rounded-xl bg-slate-900 overflow-hidden shadow-2xl min-h-[300px] relative">
            
            {/* Browser Tabs */}
            <div className="flex items-center bg-slate-800 border-b border-slate-700 px-2 pt-2 gap-1">
                <div className={`px-4 py-2 rounded-t-lg text-xs font-bold flex items-center gap-2 transition-all ${!isMaliciousTab ? 'bg-slate-700 text-blue-300 border-t border-x border-slate-600' : 'bg-transparent text-slate-500 hover:bg-slate-700/50'}`}>
                    <Globe size={12} /> MyBank.com
                </div>
                <div className={`px-4 py-2 rounded-t-lg text-xs font-bold flex items-center gap-2 transition-all ${isMaliciousTab ? 'bg-slate-700 text-red-400 border-t border-x border-slate-600' : 'bg-transparent text-slate-500 hover:bg-slate-700/50'}`}>
                    <ShieldAlert size={12} /> Free-Iphone.com
                </div>
            </div>

            {/* Address Bar */}
            <div className="bg-slate-700 p-2 flex items-center gap-4">
                <div className="flex-1 bg-slate-900 rounded px-3 py-1 text-xs font-mono text-slate-300 flex items-center justify-between">
                    <span>{isMaliciousTab ? 'http://free-iphone.com/claim' : 'https://mybank.com/dashboard'}</span>
                    {hasCookie && !isMaliciousTab && <UserCheck size={14} className="text-green-500" />}
                </div>
            </div>

            {/* Viewport Content */}
            <div className="flex-1 p-6 flex justify-center items-center bg-slate-100 relative">
                
                {/* 1. Legit Bank View */}
                {!isMaliciousTab && (
                    <div className="w-full max-w-lg bg-white rounded-lg shadow-lg p-6 border border-slate-200">
                        <div className="flex justify-between items-center mb-6 border-b pb-4">
                            <h2 className="text-xl font-bold text-blue-800">MyBank</h2>
                            <div className="text-sm text-green-600 font-semibold flex items-center gap-1">
                                <UserCheck size={16}/> Logged In
                            </div>
                        </div>
                        <div className="bg-blue-50 p-4 rounded-lg flex justify-between items-center mb-4">
                            <div className="flex items-center gap-2 text-slate-600">
                                <Wallet size={20} /> Balance
                            </div>
                            <div className="text-2xl font-bold text-slate-800">${step.csrfBalance?.toLocaleString()}</div>
                        </div>
                        <div className="text-xs text-slate-400 text-center">
                            Session Cookie: <span className="font-mono bg-slate-200 px-1 rounded text-slate-600">SID=12345</span> (Valid)
                        </div>
                    </div>
                )}

                {/* 2. Malicious Site View */}
                {isMaliciousTab && (
                    <div className="w-full max-w-lg bg-red-50 rounded-lg shadow-lg p-6 border-2 border-red-200 text-center relative overflow-hidden">
                        <h2 className="text-2xl font-extrabold text-red-600 mb-2 animate-pulse">🎉 YOU WON AN IPHONE! 🎉</h2>
                        <button className="bg-green-500 text-white font-bold py-3 px-8 rounded-full shadow-lg hover:bg-green-600 transform hover:scale-105 transition-all text-lg">
                            CLICK TO CLAIM
                        </button>
                        
                        {/* Hidden Form Visualization */}
                        <div className="absolute bottom-2 left-1/2 -translate-x-1/2 opacity-70">
                            <div className="bg-black/80 text-green-400 text-[10px] font-mono p-2 rounded border border-green-500/30 text-left">
                                <div className="flex items-center gap-1 text-slate-400 mb-1 border-b border-slate-600 pb-1">
                                    <FileCode size={10} /> Hidden Iframe / Form
                                </div>
                                &lt;form action="https://mybank.com/transfer" method="POST"&gt;<br/>
                                &nbsp;&nbsp;&lt;input name="to" value="ATTACKER" /&gt;<br/>
                                &nbsp;&nbsp;&lt;input name="amount" value="1000" /&gt;<br/>
                                &lt;/form&gt;<br/>
                                &lt;script&gt;document.forms[0].submit()&lt;/script&gt;
                            </div>
                        </div>
                    </div>
                )}

                {/* ANIMATION LAYER: Request Flying out */}
                {showRequest && (
                    <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-20 flex flex-col items-center gap-2 animate-in fade-in zoom-in duration-500">
                        <div className="bg-yellow-100 border-2 border-yellow-400 p-3 rounded-lg shadow-xl text-xs font-mono text-slate-800 flex flex-col gap-1 w-48">
                            <div className="font-bold border-b border-yellow-300 pb-1 mb-1">POST /transfer</div>
                            <div>to: ATTACKER</div>
                            <div>amount: 1000</div>
                            
                            {/* Cookie Attachment Animation */}
                            <div className={`transition-all duration-500 mt-1 pt-1 border-t border-dashed border-slate-400 flex items-center gap-2 ${showCookieAttach ? 'opacity-100 bg-green-100 text-green-700' : 'opacity-0'}`}>
                                <Cookie size={14} /> Cookie: SID=12345
                            </div>
                        </div>
                        {showCookieAttach && (
                            <div className="text-xs text-white bg-slate-800 px-2 py-1 rounded shadow">Browser Auto-Attaches Cookie</div>
                        )}
                    </div>
                )}

            </div>
        </div>

        {/* BOTTOM: Server Processing */}
        <div className={`transition-all duration-500 border-2 rounded-xl p-4 flex flex-col items-center relative
            ${currentState === 'server_process' ? 'border-red-500 bg-red-900/10' : 'border-slate-700 bg-slate-800/30 opacity-50'}
        `}>
            <div className="absolute -top-3 bg-slate-900 px-2 text-xs font-bold text-slate-400 uppercase flex items-center gap-2">
                <Server size={14} className={currentState === 'server_process' ? 'text-red-400' : 'text-slate-500'} />
                Banking Server
            </div>

            <div className="flex items-center gap-8 w-full max-w-3xl">
                <div className="bg-[#1e1e1e] p-3 rounded text-xs font-mono text-slate-300 border border-slate-600 flex-1">
                    <div className="text-purple-300">// transfer.php logic</div>
                    <div className="text-slate-500 mt-1">1. Check Cookie? <span className={currentState === 'server_process' ? 'text-green-400 font-bold' : ''}>{currentState === 'server_process' ? 'YES (Valid)' : '...'}</span></div>
                    <div className="text-slate-500">2. Check CSRF Token? <span className="text-red-400 font-bold">NO (Missing)</span></div>
                    <div className={`mt-2 p-1 rounded ${currentState === 'server_process' ? 'bg-red-900/40 text-red-200' : ''}`}>
                        3. Execute Transfer(User, Attacker, 1000)
                    </div>
                </div>
                
                {currentState === 'server_process' && (
                    <div className="flex flex-col items-center text-red-500 animate-pulse">
                        <Wallet size={32} />
                        <span className="font-bold text-sm">-$1,000</span>
                    </div>
                )}
            </div>
        </div>

    </div>
  );
};
