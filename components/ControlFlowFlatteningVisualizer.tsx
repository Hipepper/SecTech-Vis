import React from 'react';
import { AnimationStep } from '../types';
import { GitBranch, Zap, Code2, Layers, ArrowRight, GitMerge, Workflow, Lock, Eye, Shield } from 'lucide-react';

interface ControlFlowFlatteningVisualizerProps {
  step: AnimationStep;
}

export const ControlFlowFlatteningVisualizer: React.FC<ControlFlowFlatteningVisualizerProps> = ({ step }) => {
  const cfwStep = step.cfwStep || 'original';
  
  return (
    <div className="flex flex-col gap-6 w-full max-w-5xl mx-auto p-4">
      
      {/* 1. Original vs Flattened Control Flow Comparison */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Original Control Flow (Left) */}
        <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-6 flex flex-col gap-4 shadow-lg">
          <div className="flex items-center gap-2 border-b border-slate-700 pb-2 mb-2">
            <GitBranch size={18} className="text-blue-400" />
            <h3 className="text-sm font-bold text-slate-200">原始控制流 (Original)</h3>
          </div>
          
          {/* Original Flow Diagram */}
          <div className="flex flex-col gap-3 items-center min-h-64 justify-center">
            
            {/* Block Entry */}
            <div className={`px-4 py-3 rounded-lg border-2 text-center font-mono text-xs transition-all duration-500
              ${cfwStep === 'original' ? 'bg-blue-900/40 border-blue-400 text-blue-100' : 'bg-slate-800 border-slate-600 text-slate-400'}
            `}>
              Entry<br/><span className="text-[10px]">if (id &lt; 1000)</span>
            </div>
            
            {/* Arrow Down */}
            <ArrowRight size={16} className="rotate-90 text-slate-600" />
            
            {/* Two Branches */}
            <div className="flex gap-4 w-full justify-center">
              {/* Left Branch */}
              <div className="flex flex-col items-center gap-2">
                <div className={`px-3 py-2 rounded-lg border-2 text-center font-mono text-[10px] transition-all duration-500
                  ${cfwStep === 'original' && step.cfwBlocks?.[0]?.state === 'active' ? 'bg-red-900/40 border-red-400 text-red-100 scale-105' : 'bg-slate-800 border-slate-600 text-slate-400'}
                `}>
                  log_event()
                </div>
              </div>
              
              {/* Right Branch */}
              <div className="flex flex-col items-center gap-2">
                <div className={`px-3 py-2 rounded-lg border-2 text-center font-mono text-[10px] transition-all duration-500
                  ${cfwStep === 'original' && step.cfwBlocks?.[1]?.state === 'active' ? 'bg-green-900/40 border-green-400 text-green-100 scale-105' : 'bg-slate-800 border-slate-600 text-slate-400'}
                `}>
                  check_password()
                </div>
              </div>
            </div>
            
            {/* Arrow Down */}
            <ArrowRight size={16} className="rotate-90 text-slate-600" />
            
            {/* Return Block */}
            <div className={`px-4 py-3 rounded-lg border-2 text-center font-mono text-xs transition-all duration-500
              ${['original', 'analysis'].includes(cfwStep) ? 'bg-slate-700 border-slate-500 text-slate-200' : 'bg-slate-800 border-slate-600 text-slate-400'}
            `}>
              return 0/1
            </div>
          </div>

          <div className="text-[10px] text-slate-500 italic p-3 bg-slate-800/50 rounded border border-slate-700">
            💡 易于理解：清晰的分支结构，条件语句一目了然
          </div>
        </div>

        {/* Flattened Control Flow (Right) */}
        <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-6 flex flex-col gap-4 shadow-lg">
          <div className="flex items-center gap-2 border-b border-slate-700 pb-2 mb-2">
            <Workflow size={18} className="text-purple-400" />
            <h3 className="text-sm font-bold text-slate-200">扁平化控制流 (Flattened)</h3>
          </div>
          
          {/* Flattened Flow Diagram */}
          <div className="flex flex-col gap-2 min-h-64 justify-start">
            
            {/* Dispatch State Machine */}
            <div className={`p-3 rounded-lg border-2 font-mono text-[10px] transition-all duration-500
              ${['flatten', 'dispatch_init', 'dispatch_loop', 'obfuscated'].includes(cfwStep) ? 'bg-purple-900/40 border-purple-400 text-purple-100' : 'bg-slate-800 border-slate-600 text-slate-400'}
            `}>
              <div className="font-bold mb-2">while (1) &#123;</div>
              <div className="ml-3">switch(state) &#123;</div>
            </div>

            {/* State Cases */}
            {[0, 1, 2, 3, 4, 5, 6, 7].map((caseNum) => (
              <div key={caseNum} className={`ml-4 p-2 rounded border text-[9px] font-mono transition-all duration-500
                ${cfwStep === 'dispatch_loop' && step.cfwDispatch?.value === caseNum ? 'bg-yellow-900/40 border-yellow-400 text-yellow-100 scale-105' : 'bg-slate-800 border-slate-700 text-slate-400'}
              `}>
                case {caseNum}: // Block {caseNum}
              </div>
            ))}

            {/* State Cases End */}
            <div className={`ml-3 p-2 rounded border text-[9px] font-mono transition-all duration-500
              ${['obfuscated', 'comparison'].includes(cfwStep) ? 'bg-slate-700 border-slate-600 text-slate-300' : 'bg-slate-800 border-slate-700 text-slate-400'}
            `}>
              &#125; // switch end<br/>&#125; // while end
            </div>
          </div>

          <div className="text-[10px] text-slate-500 italic p-3 bg-slate-800/50 rounded border border-slate-700">
            🔒 难以理解：所有分支变成状态转换，缺乏明显的逻辑意图
          </div>
        </div>

      </div>

      {/* 2. Animation Sequence */}
      <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-6 shadow-lg">
        <div className="flex items-center gap-2 border-b border-slate-700 pb-3 mb-4">
          <Zap size={18} className="text-yellow-400" />
          <h3 className="text-sm font-bold text-slate-200">转换步骤 (Transformation Steps)</h3>
        </div>

        <div className="space-y-4">
          {/* Step 1: Original Analysis */}
          <div className={`p-4 rounded-lg border-l-4 transition-all duration-500
            ${cfwStep === 'original' ? 'bg-blue-900/20 border-blue-500 shadow-lg' : 'bg-slate-800/30 border-slate-700 opacity-60'}
          `}>
            <div className="flex items-start gap-3">
              <div className={`p-2 rounded-full ${cfwStep === 'original' ? 'bg-blue-600 text-white' : 'bg-slate-700 text-slate-400'}`}>
                <Code2 size={16} />
              </div>
              <div className="flex-1">
                <h4 className="text-sm font-bold text-slate-100">1. 源代码分析</h4>
                <p className="text-[11px] text-slate-400 mt-1">识别基本块、条件分支和循环结构</p>
              </div>
            </div>
          </div>

          {/* Step 2: Control Flow Analysis */}
          <div className={`p-4 rounded-lg border-l-4 transition-all duration-500
            ${cfwStep === 'analysis' ? 'bg-purple-900/20 border-purple-500 shadow-lg' : 'bg-slate-800/30 border-slate-700 opacity-60'}
          `}>
            <div className="flex items-start gap-3">
              <div className={`p-2 rounded-full ${cfwStep === 'analysis' ? 'bg-purple-600 text-white' : 'bg-slate-700 text-slate-400'}`}>
                <GitBranch size={16} />
              </div>
              <div className="flex-1">
                <h4 className="text-sm font-bold text-slate-100">2. 控制流分析</h4>
                <p className="text-[11px] text-slate-400 mt-1">绘制所有可能的执行路径和分支关系</p>
              </div>
            </div>
          </div>

          {/* Step 3: Flattening */}
          <div className={`p-4 rounded-lg border-l-4 transition-all duration-500
            ${cfwStep === 'flatten' ? 'bg-yellow-900/20 border-yellow-500 shadow-lg' : 'bg-slate-800/30 border-slate-700 opacity-60'}
          `}>
            <div className="flex items-start gap-3">
              <div className={`p-2 rounded-full ${cfwStep === 'flatten' ? 'bg-yellow-600 text-white' : 'bg-slate-700 text-slate-400'}`}>
                <Layers size={16} />
              </div>
              <div className="flex-1">
                <h4 className="text-sm font-bold text-slate-100">3. 扁平化处理</h4>
                <p className="text-[11px] text-slate-400 mt-1">将所有基本块转换为状态机中的状态 (case 0~7)</p>
              </div>
            </div>
          </div>

          {/* Step 4: Dispatch Initialization */}
          <div className={`p-4 rounded-lg border-l-4 transition-all duration-500
            ${cfwStep === 'dispatch_init' ? 'bg-indigo-900/20 border-indigo-500 shadow-lg' : 'bg-slate-800/30 border-slate-700 opacity-60'}
          `}>
            <div className="flex items-start gap-3">
              <div className={`p-2 rounded-full ${cfwStep === 'dispatch_init' ? 'bg-indigo-600 text-white' : 'bg-slate-700 text-slate-400'}`}>
                <Lock size={16} />
              </div>
              <div className="flex-1">
                <h4 className="text-sm font-bold text-slate-100">4. 分派循环初始化</h4>
                <p className="text-[11px] text-slate-400 mt-1">初始化状态变量 (state = 0)，进入无限循环</p>
              </div>
            </div>
          </div>

          {/* Step 5: Dispatch Loop */}
          <div className={`p-4 rounded-lg border-l-4 transition-all duration-500
            ${cfwStep === 'dispatch_loop' ? 'bg-cyan-900/20 border-cyan-500 shadow-lg' : 'bg-slate-800/30 border-slate-700 opacity-60'}
          `}>
            <div className="flex items-start gap-3">
              <div className={`p-2 rounded-full ${cfwStep === 'dispatch_loop' ? 'bg-cyan-600 text-white' : 'bg-slate-700 text-slate-400'}`}>
                <GitMerge size={16} />
              </div>
              <div className="flex-1">
                <h4 className="text-sm font-bold text-slate-100">5. 分派循环执行</h4>
                <p className="text-[11px] text-slate-400 mt-1">根据当前状态值跳转到对应的 case 块并执行</p>
              </div>
            </div>
          </div>

          {/* Step 6: Obfuscated Result */}
          <div className={`p-4 rounded-lg border-l-4 transition-all duration-500
            ${cfwStep === 'obfuscated' ? 'bg-red-900/20 border-red-500 shadow-lg' : 'bg-slate-800/30 border-slate-700 opacity-60'}
          `}>
            <div className="flex items-start gap-3">
              <div className={`p-2 rounded-full ${cfwStep === 'obfuscated' ? 'bg-red-600 text-white' : 'bg-slate-700 text-slate-400'}`}>
                <Eye size={16} />
              </div>
              <div className="flex-1">
                <h4 className="text-sm font-bold text-slate-100">6. 混淆完成</h4>
                <p className="text-[11px] text-slate-400 mt-1">原始逻辑被隐藏，变成难以追踪的状态机</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Technical Details & OLLVM Info */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Effects & Challenges */}
        <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-6 shadow-lg">
          <div className="flex items-center gap-2 border-b border-slate-700 pb-3 mb-4">
            <Shield size={18} className="text-green-400" />
            <h3 className="text-sm font-bold text-slate-200">混淆效果 (Obfuscation Effects)</h3>
          </div>

          <div className="space-y-3">
            <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
              <div className="text-xs font-bold text-green-400 mb-1">代码复杂度</div>
              <div className="text-[10px] text-slate-400">
                <div>• 原始代码：线性易懂的分支结构</div>
                <div>• 混淆后：复杂的状态机，难以追踪执行流</div>
                <div className="mt-2 text-slate-500">复杂度增加 200%-500%，取决于分支数量</div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
              <div className="text-xs font-bold text-yellow-400 mb-1">逆向工程难度</div>
              <div className="text-[10px] text-slate-400">
                <div>• 难以识别真实的控制流</div>
                <div>• 状态转换关系混乱</div>
                <div className="mt-2 text-slate-500">增加 10~100 倍的逆向分析时间</div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
              <div className="text-xs font-bold text-red-400 mb-1">执行速度</div>
              <div className="text-[10px] text-slate-400">
                <div>• 性能略有下降 (5-15%)</div>
                <div>• 额外的 switch 分派开销</div>
                <div>• 可通过编译器优化缓解</div>
              </div>
            </div>
          </div>
        </div>

        {/* OLLVM & Implementation */}
        <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-6 shadow-lg">
          <div className="flex items-center gap-2 border-b border-slate-700 pb-3 mb-4">
            <Code2 size={18} className="text-orange-400" />
            <h3 className="text-sm font-bold text-slate-200">OLLVM 实现 (OLLVM Framework)</h3>
          </div>

          <div className="space-y-3">
            <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
              <div className="text-xs font-bold text-orange-400 mb-1">什么是 OLLVM？</div>
              <div className="text-[10px] text-slate-400">
                Obfuscator-LLVM 是基于 LLVM 编译器框架的开源代码混淆工具，支持多种混淆技术。
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
              <div className="text-xs font-bold text-cyan-400 mb-1">核心功能</div>
              <div className="text-[10px] text-slate-400">
                <div>✓ 控制流扁平化 (Control Flow Flattening)</div>
                <div>✓ 指令替换 (Instruction Substitution)</div>
                <div>✓ 假分支注入 (Bogus Control Flow)</div>
                <div>✓ 字符串混淆 (String Obfuscation)</div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
              <div className="text-xs font-bold text-purple-400 mb-1">使用场景</div>
              <div className="text-[10px] text-slate-400">
                <div>• Android/iOS APP 保护</div>
                <div>• 恶意软件对抗（检测躲避）</div>
                <div>• 商业代码保密</div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
              <div className="text-xs font-bold text-red-400 mb-1">对抗技术</div>
              <div className="text-[10px] text-slate-400">
                <div>• 动态污点追踪 (Dynamic Taint)</div>
                <div>• 符号执行 (Symbolic Execution)</div>
                <div>• 二进制分析工具 (Ghidra, IDA Pro)</div>
              </div>
            </div>
          </div>
        </div>

      </div>

      {/* 4. Code Complexity Comparison */}
      <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-6 shadow-lg">
        <div className="flex items-center gap-2 border-b border-slate-700 pb-3 mb-4">
          <Layers size={18} className="text-blue-400" />
          <h3 className="text-sm font-bold text-slate-200">代码复杂度分析 (Complexity Analysis)</h3>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="p-4 rounded-lg bg-blue-900/20 border border-blue-700">
            <div className="text-2xl font-bold text-blue-400">
              {step.cfwComplexity?.original || 8}
            </div>
            <div className="text-[10px] text-slate-400 mt-1">原始代码行数</div>
            <div className="text-[9px] text-slate-500 mt-2">清晰的分支结构，易于维护</div>
          </div>

          <div className={`p-4 rounded-lg transition-all duration-500 ${cfwStep === 'obfuscated' ? 'bg-red-900/20 border border-red-700 scale-105' : 'bg-slate-800 border border-slate-700'}`}>
            <div className={`text-2xl font-bold ${cfwStep === 'obfuscated' ? 'text-red-400' : 'text-slate-400'}`}>
              {step.cfwComplexity?.flattened || 35}
            </div>
            <div className="text-[10px] text-slate-400 mt-1">混淆后代码行数</div>
            <div className="text-[9px] text-slate-500 mt-2">400% 复杂度增加，难以理解</div>
          </div>
        </div>
      </div>

    </div>
  );
};
