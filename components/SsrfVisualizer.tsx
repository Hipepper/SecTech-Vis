
import React from 'react';
import { AnimationStep } from '../types';
import { Globe, Server, Lock, ArrowRight, ShieldAlert, Laptop, Database, ArrowLeft } from 'lucide-react';

interface SsrfVisualizerProps {
  step: AnimationStep;
}

export const SsrfVisualizer: React.FC<SsrfVisualizerProps> = ({ step }) => {
  const ssrfStep = step.ssrfStep || 'input';

  // Animation States
  const showAttackerRequest = ['request_out', 'processing', 'request_in', 'response_internal', 'response_final'].includes(ssrfStep);
  const showProcessing = ['processing', 'request_in', 'response_internal', 'response_final'].includes(ssrfStep);
  const showInternalRequest = ['request_in', 'response_internal', 'response_final'].includes(ssrfStep);
  const showInternalResponse = ['response_internal', 'response_final'].includes(ssrfStep);
  const showFinalResponse = ['response_final'].includes(ssrfStep);

  return (
    <div className="flex flex-col gap-8 w-full max-w-6xl mx-auto p-4">
        
        {/* Main Diagram */}
        <div className="relative grid grid-cols-1 md:grid-cols-3 gap-8 items-stretch min-h-[300px]">
            
            {/* 1. Attacker */}
            <div className="flex flex-col gap-4">
                <div className="flex items-center gap-2 text-red-400 font-bold uppercase tracking-wider text-sm">
                    <Laptop size={18} /> Attacker (Public)
                </div>
                <div className="flex-1 bg-slate-900 border border-slate-700 rounded-xl p-4 flex flex-col items-center justify-between relative shadow-lg">
                    <div className="w-full bg-slate-800 p-3 rounded text-xs font-mono text-slate-300 break-all border border-slate-600">
                        <div className="text-[10px] text-slate-500 mb-1 uppercase">Browser URL</div>
                        http://vuln.com/fetch?url=<span className="text-red-400 font-bold">{step.ssrfPayload || "..."}</span>
                    </div>

                    <div className="mt-4">
                        <Globe size={48} className="text-slate-600" />
                    </div>

                    {/* Final Response Display */}
                    <div className={`mt-4 w-full bg-black border border-green-500/30 p-2 rounded min-h-[60px] transition-all duration-500 ${showFinalResponse ? 'opacity-100' : 'opacity-0'}`}>
                         <div className="text-[10px] text-green-500 mb-1 uppercase">Response Body</div>
                         <div className="text-xs font-mono text-green-300">{step.ssrfInternalData}</div>
                    </div>
                </div>
            </div>

            {/* Connection 1: Attacker -> Server */}
            <div className="absolute left-[33%] top-1/2 -translate-x-1/2 -translate-y-1/2 z-20 hidden md:block">
                {/* Request Arrow */}
                <div className={`transition-all duration-500 ${showAttackerRequest && !showFinalResponse ? 'opacity-100 translate-x-2' : 'opacity-0'}`}>
                    <div className="bg-red-600 text-white p-2 rounded-full shadow-[0_0_15px_rgba(220,38,38,0.5)]">
                        <ArrowRight size={20} />
                    </div>
                </div>
                 {/* Response Arrow */}
                 <div className={`transition-all duration-500 absolute top-0 ${showFinalResponse ? 'opacity-100 -translate-x-2' : 'opacity-0'}`}>
                    <div className="bg-green-600 text-white p-2 rounded-full shadow-[0_0_15px_rgba(22,163,74,0.5)]">
                        <ArrowLeft size={20} />
                    </div>
                </div>
            </div>

            {/* 2. Vulnerable Server (The Proxy) */}
            <div className="flex flex-col gap-4">
                <div className="flex items-center gap-2 text-blue-400 font-bold uppercase tracking-wider text-sm">
                    <Server size={18} /> Public Web Server
                </div>
                <div className={`flex-1 bg-slate-900 border-2 rounded-xl p-4 flex flex-col items-center relative shadow-lg transition-colors duration-300 ${showProcessing ? 'border-blue-500 bg-blue-900/10' : 'border-slate-700'}`}>
                    
                    {/* Code Execution */}
                    <div className="w-full bg-[#1e1e1e] p-3 rounded text-xs font-mono text-slate-300 border border-slate-600 mb-4">
                        <div className="text-purple-300">$url = $_GET['url'];</div>
                        <div className={`transition-colors duration-300 ${showInternalRequest ? 'text-yellow-300 bg-yellow-900/20' : 'text-slate-500'}`}>
                            $data = file_get_contents($url);
                        </div>
                        <div className="text-slate-500 mt-1">// Server acts as proxy</div>
                    </div>

                    <Server size={48} className={showProcessing ? 'text-blue-400 animate-pulse' : 'text-slate-600'} />
                    
                    <div className="mt-auto mb-2 text-center text-xs text-slate-400">
                        Authorized to access Internal Network
                    </div>
                </div>
            </div>

            {/* Connection 2: Server -> Internal */}
            <div className="absolute right-[33%] top-1/2 -translate-x-1/2 -translate-y-1/2 z-20 hidden md:block">
                 {/* Request Arrow */}
                 <div className={`transition-all duration-500 ${showInternalRequest && !showInternalResponse ? 'opacity-100 translate-x-2' : 'opacity-0'}`}>
                    <div className="bg-yellow-600 text-white p-2 rounded-full shadow-[0_0_15px_rgba(202,138,4,0.5)]">
                        <ArrowRight size={20} />
                    </div>
                </div>
                 {/* Response Arrow */}
                 <div className={`transition-all duration-500 absolute top-0 ${showInternalResponse && !showFinalResponse ? 'opacity-100 -translate-x-2' : 'opacity-0'}`}>
                    <div className="bg-green-600 text-white p-2 rounded-full shadow-[0_0_15px_rgba(22,163,74,0.5)]">
                        <ArrowLeft size={20} />
                    </div>
                </div>
            </div>

            {/* 3. Internal Target (Private) */}
            <div className="flex flex-col gap-4">
                <div className="flex items-center gap-2 text-green-400 font-bold uppercase tracking-wider text-sm">
                    <Lock size={18} /> Internal / Private
                </div>
                <div className="flex-1 bg-slate-900 border-2 border-dashed border-slate-600 rounded-xl p-4 flex flex-col items-center justify-center relative shadow-inner">
                    
                    {/* Firewall Label */}
                    <div className="absolute top-2 right-2 flex items-center gap-1 text-[10px] text-orange-500 border border-orange-500/50 px-2 py-1 rounded bg-orange-900/10">
                        <ShieldAlert size={12} /> Firewall: Block Ext.
                    </div>

                    <div className={`transition-all duration-500 transform ${showInternalRequest ? 'scale-110' : 'scale-100'}`}>
                         <Database size={48} className={showInternalRequest ? 'text-green-400' : 'text-slate-700'} />
                    </div>

                    <div className="mt-4 text-center">
                        <div className="text-sm font-bold text-slate-200">Admin Panel / DB</div>
                        <div className="text-xs font-mono text-slate-500 mt-1">127.0.0.1:8080</div>
                    </div>

                    {showInternalRequest && (
                        <div className="mt-4 bg-green-900/20 text-green-300 text-xs px-2 py-1 rounded border border-green-500/30 animate-pulse">
                            Request from Trusted Server (Allowed)
                        </div>
                    )}
                </div>
            </div>

        </div>

        {/* Explanation Footer */}
        <div className="bg-slate-900 border border-slate-700 rounded-xl p-4 flex items-center justify-center text-center">
            <p className="text-sm text-slate-300 max-w-3xl">
                {ssrfStep === 'input' && "The attacker identifies a parameter that accepts a URL. They input a local loopback address (127.0.0.1) targeting an internal admin panel."}
                {ssrfStep === 'request_out' && "The malicious request is sent to the public-facing web server."}
                {ssrfStep === 'processing' && "The server executes the vulnerable code, preparing to fetch the content of the provided URL."}
                {ssrfStep === 'request_in' && "The server, trusted by the internal network, sends a request to the internal Admin Panel. The firewall allows this because it originates from inside."}
                {ssrfStep === 'response_internal' && "The internal Admin Panel processes the request and returns sensitive data (e.g., admin credentials or dashboard HTML) to the server."}
                {ssrfStep === 'response_final' && "The server blindly relays this sensitive internal data back to the attacker in the HTTP response."}
            </p>
        </div>

    </div>
  );
};
