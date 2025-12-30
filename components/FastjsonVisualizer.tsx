import React from 'react';
import { AnimationStep } from '../types';
import { Code, Server, Database, ArrowDown, Zap, Terminal } from 'lucide-react';

interface FastjsonVisualizerProps {
  step: AnimationStep;
}

export const FastjsonVisualizer: React.FC<FastjsonVisualizerProps> = ({ step }) => {
  const currentState = step.fjsonStep || 'input';

  return (
    <div className="flex flex-col gap-6 w-full max-w-5xl mx-auto p-4">

      {/* 1. CLIENT / ATTACKER */}
      <div className={`
        flex flex-col p-6 rounded-xl border-2 transition-all duration-500 relative min-h-[160px]
        ${currentState === 'input' || currentState === 'parsing' ? 'border-red-500 bg-red-900/10 opacity-100' : 'border-slate-700 bg-slate-800/30 opacity-60'}
      `}>
        <div className="flex items-center gap-2 mb-4 text-slate-300 font-bold border-b border-slate-600 pb-2">
          <Code size={20} className="text-red-400" /> Attacker / Malicious Input
        </div>

        <div className="flex flex-col gap-4">
          <div className="bg-black rounded p-3 border border-slate-600 shadow-md">
            <div className="text-[10px] text-slate-500 uppercase font-bold mb-2">Crafted JSON Payload (autoType enabled)</div>
            <div className="text-xs font-mono text-yellow-300 break-all leading-relaxed max-h-[120px] overflow-y-auto">
              &#123;<br/>
              &nbsp;&nbsp;<span className="text-blue-300">"@type"</span>: <span className="text-red-400">"{step.fjsonValue || 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplateImpl'}"</span>,<br/>
              &nbsp;&nbsp;<span className="text-blue-300">"_bytecodes"</span>: [...],<br/>
              &nbsp;&nbsp;<span className="text-blue-300">"_name"</span>: <span className="text-red-400">"Pwned"</span>,<br/>
              &nbsp;&nbsp;<span className="text-blue-300">"_tfactory"</span>: &#123;...<span className="text-red-400 font-bold">GADGET CHAIN</span>...&#125;<br/>
              &#125;
            </div>
          </div>
        </div>

        {currentState === 'parsing' && (
          <div className="absolute -bottom-6 left-1/2 -translate-x-1/2 z-10 text-red-500 animate-bounce">
            <ArrowDown size={40} strokeWidth={3} />
          </div>
        )}
      </div>

      {/* 2. SERVER (Java Backend) */}
      <div className={`
        flex flex-col p-6 rounded-xl border-2 transition-all duration-500 relative min-h-[200px]
        ${['parsing', 'template_injection', 'getvalue'].includes(currentState) ? 'border-blue-500 bg-blue-900/10 opacity-100 shadow-xl' : 'border-slate-700 bg-slate-800/30 opacity-60'}
      `}>
        <div className="flex items-center gap-2 mb-4 text-slate-300 font-bold border-b border-slate-600 pb-2">
          <Server size={20} className="text-blue-400" /> Backend Server (Java)
        </div>

        <div className="flex flex-col lg:flex-row gap-6">

          {/* Parsing & Deserialization */}
          <div className="lg:w-1/2 flex flex-col gap-2">
            <div className="text-[10px] text-slate-500 uppercase font-bold">JSON Parse & Deserialization</div>
            <div className="bg-[#1e1e1e] p-4 rounded border border-slate-600 font-mono text-sm overflow-x-auto flex-1 flex flex-col justify-center">
              <div className="text-slate-500 mb-2">// Fastjson Processing</div>
              <div className="text-blue-300">JSON.parseObject(jsonStr,</div>
              <div className="text-blue-300 ml-4">User.class,</div>
              <div className="text-red-400 font-bold ml-4">Feature.AutoType<span className="text-yellow-300"> // ← VULNERABILITY!</span></div>
              <div className="text-blue-300">);</div>

              {['parsing', 'template_injection', 'getvalue'].includes(currentState) && (
                <div className="mt-4 pt-4 border-t border-slate-700">
                  <div className="text-green-400 text-[10px] font-bold mb-1">PARSING @type:</div>
                  <div className="text-yellow-300 text-xs break-all">
                    {step.fjsonValue || 'com.sun.org.apache.xalan...TemplateImpl'}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Reflection & Instantiation */}
          <div className="lg:w-1/2 flex flex-col gap-2">
            <div className="text-[10px] text-slate-500 uppercase font-bold">Reflection & Class Loading</div>
            <div className="bg-[#1e1e1e] p-4 rounded border border-slate-600 font-mono text-sm flex-1 flex flex-col justify-center">
              {currentState === 'template_injection' && (
                <div className="animate-in zoom-in duration-500">
                  <div className="text-green-400 mb-2">✓ Class found:</div>
                  <div className="text-yellow-300 text-xs mb-3">TemplateImpl (Gadget)</div>
                  <div className="text-slate-500 text-xs">↓</div>
                  <div className="text-purple-400 text-xs mt-2">Constructor.newInstance()</div>
                  <div className="text-slate-500 text-xs">↓</div>
                  <div className="text-blue-400 text-xs mt-2">Setter methods invoked</div>
                </div>
              )}
              {currentState === 'getvalue' && (
                <div className="animate-in slide-in-from-left duration-500">
                  <div className="text-blue-400 font-bold mb-2">Getter Invocation:</div>
                  <div className="text-yellow-300 text-xs break-all">
                    getValue() → FreeMarker.render()
                  </div>
                  <div className="text-green-400 text-xs mt-3">Template expr loaded:</div>
                  <div className="text-red-400 text-xs break-all">
                    &lt;#assign ex="...Execute"&gt;
                  </div>
                </div>
              )}
              {!['parsing', 'template_injection', 'getvalue'].includes(currentState) && (
                <div className="text-slate-600 italic text-xs">Waiting for @type field...</div>
              )}
            </div>
          </div>

        </div>

        {['parsing', 'template_injection'].includes(currentState) && (
          <div className="absolute -bottom-6 left-1/2 -translate-x-1/2 z-10 text-blue-500 animate-bounce">
            <ArrowDown size={40} strokeWidth={3} />
          </div>
        )}
      </div>

      {/* 3. TEMPLATE ENGINE EXECUTION */}
      {['template_eval', 'rce'].includes(currentState) && (
        <div className={`
          flex flex-col p-6 rounded-xl border-2 transition-all duration-500
          ${currentState === 'rce' ? 'border-red-500 bg-red-900/10 opacity-100' : 'border-yellow-600 bg-yellow-900/10 opacity-90'}
        `}>
          <div className="flex items-center gap-2 mb-4 text-slate-300 font-bold border-b border-slate-600 pb-2">
            <Zap size={20} className="text-yellow-400" /> Template Engine (FreeMarker / Velocity)
          </div>

          <div className="bg-[#1e1e1e] p-4 rounded border border-slate-600 font-mono text-sm mb-4">
            <div className="text-slate-500 mb-2">// Template Evaluation</div>
            <div className="text-green-400">
              &lt;#assign ex=<span className="text-yellow-300">"freemarker.template.utility.Execute"</span>?new()&gt;
            </div>
            <div className="text-slate-500 text-xs mt-2 italic">↓ Evaluating expression...</div>
            <div className="text-blue-400 mt-2">
              $&#123; ex(<span className="text-red-400">"touch /tmp/pwned"</span>) &#125;
            </div>
          </div>

          {currentState === 'rce' && (
            <div>
              <div className="text-[10px] text-slate-500 uppercase font-bold mb-2">System Command Execution</div>
              <div className="bg-black p-4 rounded border border-red-500 font-mono text-xs">
                <div className="flex items-center gap-2 text-slate-500 border-b border-slate-800 pb-2 mb-2">
                  <Terminal size={12} /> Shell Output
                </div>
                <div className="text-green-400 animate-in fade-in">
                  $ <span className="text-yellow-400">whoami</span><br/>
                  <span className="text-white">root</span><br/>
                  <br/>
                  $ <span className="text-yellow-400">id</span><br/>
                  <span className="text-white">uid=0(root) gid=0(root) groups=0(root)</span><br/>
                  <br/>
                  $ <span className="text-yellow-400">cat /tmp/pwned</span><br/>
                  <span className="text-white">System compromised</span><br/>
                  <span className="text-green-400">$ _</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* INFO BOX */}
      {currentState === 'input' && (
        <div className="bg-blue-900/20 border border-blue-500/50 rounded-xl p-4 text-xs text-slate-300">
          <div className="font-bold text-blue-400 mb-2">Fastjson CVE-2022-24765 / CVE-2023-22515</div>
          <p>
            Fastjson's <span className="text-yellow-300 font-mono">autoType</span> feature allows arbitrary class instantiation from JSON. 
            When enabled, attackers can inject <span className="text-red-400">@type</span> fields pointing to gadget classes, 
            enabling template injection and remote code execution through magic methods and gadget chains.
          </p>
        </div>
      )}

    </div>
  );
};
