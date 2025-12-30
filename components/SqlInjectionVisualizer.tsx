
import React from 'react';
import { AnimationStep } from '../types';
import { Globe, Server, Database, ArrowDown, Search } from 'lucide-react';

interface SqlInjectionVisualizerProps {
  step: AnimationStep;
}

export const SqlInjectionVisualizer: React.FC<SqlInjectionVisualizerProps> = ({ step }) => {
  const currentState = step.sqliStep || 'input';
  
  return (
    <div className="flex flex-col gap-6 w-full max-w-5xl mx-auto p-4">
        
        {/* 1. CLIENT / BROWSER */}
        <div className={`
            flex flex-col p-6 rounded-xl border-2 transition-all duration-500 relative min-h-[160px]
            ${currentState === 'input' || currentState === 'request' ? 'border-blue-500 bg-blue-900/10 opacity-100' : 'border-slate-700 bg-slate-800/30 opacity-60'}
        `}>
            <div className="flex items-center gap-2 mb-4 text-slate-300 font-bold border-b border-slate-600 pb-2">
                <Globe size={20} className="text-blue-400" /> Client (Browser)
            </div>
            
            <div className="flex flex-col md:flex-row gap-6">
                <div className="flex-1">
                    <div className="bg-white rounded p-3 flex items-center gap-3 mb-4 shadow-md">
                        <div className="bg-slate-200 p-1.5 rounded text-slate-500">
                            <Search size={16}/>
                        </div>
                        <div className="flex-1 text-sm font-mono text-slate-700 overflow-hidden text-ellipsis whitespace-nowrap">
                            http://vulnerable-site.com/user?id=<span className="font-bold text-red-600">{step.sqliInput}</span>
                        </div>
                    </div>
                </div>

                <div className="flex-1">
                    <div className="bg-slate-900 p-3 rounded border border-slate-600 h-full flex flex-col justify-center">
                        <div className="text-[10px] text-slate-500 uppercase font-bold mb-1">User Input Field</div>
                        <div className="bg-black border border-slate-500 p-2 rounded text-base text-white font-mono">
                            {step.sqliInput}
                            <span className="animate-pulse ml-0.5">|</span>
                        </div>
                    </div>
                </div>
            </div>

            {currentState === 'request' && (
                <div className="absolute -bottom-6 left-1/2 -translate-x-1/2 z-10 text-blue-500 animate-bounce">
                    <ArrowDown size={40} strokeWidth={3} />
                </div>
            )}
        </div>

        {/* 2. SERVER (PHP/NODE) */}
        <div className={`
            flex flex-col p-6 rounded-xl border-2 transition-all duration-500 relative min-h-[180px]
            ${currentState === 'query' ? 'border-purple-500 bg-purple-900/10 opacity-100 shadow-xl scale-[1.02]' : 'border-slate-700 bg-slate-800/30 opacity-60'}
        `}>
            <div className="flex items-center gap-2 mb-4 text-slate-300 font-bold border-b border-slate-600 pb-2">
                <Server size={20} className="text-purple-400" /> Backend Server
            </div>

            <div className="bg-[#1e1e1e] p-4 rounded border border-slate-600 font-mono text-sm overflow-x-auto shadow-inner">
                <div className="text-slate-500 mb-2">// backend.php</div>
                <div className="text-purple-300">$id = $_GET['id'];</div>
                <div className="text-slate-400 mt-2 italic">// VULNERABLE: Direct string concatenation without sanitization</div>
                <div className="text-green-300 whitespace-pre-wrap break-all mt-1 p-2 bg-black/20 rounded border border-white/5">
                    $sql = "SELECT * FROM users WHERE id = " . <span className="text-red-400 font-bold border-b-2 border-red-500 bg-red-900/20 px-1">{step.sqliInput}</span>;
                </div>
            </div>
            
            {currentState === 'query' && (
                <div className="absolute top-6 right-6 text-xs text-purple-200 bg-purple-900/40 px-3 py-1 rounded border border-purple-500/30 animate-pulse">
                    Constructing Malicious Query...
                </div>
            )}

            {currentState === 'query' && (
                <div className="absolute -bottom-6 left-1/2 -translate-x-1/2 z-10 text-purple-500 animate-bounce">
                    <ArrowDown size={40} strokeWidth={3} />
                </div>
            )}
        </div>

        {/* 3. DATABASE */}
        <div className={`
            flex flex-col p-6 rounded-xl border-2 transition-all duration-500 min-h-[200px]
            ${currentState === 'db' || currentState === 'response' ? 'border-red-500 bg-red-900/10 opacity-100' : 'border-slate-700 bg-slate-800/30 opacity-60'}
        `}>
            <div className="flex items-center gap-2 mb-4 text-slate-300 font-bold border-b border-slate-600 pb-2">
                <Database size={20} className="text-red-400" /> SQL Database
            </div>

            <div className="flex flex-col lg:flex-row gap-6">
                
                {/* Executed Query View */}
                <div className="lg:w-1/3 flex flex-col gap-2">
                    <div className="bg-black/40 p-3 rounded border border-slate-600 h-full">
                        <div className="text-[10px] text-slate-500 uppercase font-bold mb-2">Final Executed Query</div>
                        <div className="font-mono text-sm text-yellow-300 break-all leading-relaxed">
                            SELECT * FROM users WHERE id = <span className="text-red-400 font-bold bg-red-900/20 px-1">{step.sqliInput}</span>
                        </div>
                    </div>
                </div>

                {/* The Table Result */}
                <div className="lg:w-2/3 flex flex-col gap-2">
                    <div className="text-[10px] text-slate-500 uppercase font-bold">Query Result Set</div>
                    <div className="bg-white text-black rounded-lg overflow-hidden text-sm shadow-lg">
                        <table className="w-full">
                            <thead className="bg-slate-200 font-bold border-b border-slate-300">
                                <tr>
                                    <td className="p-2">ID</td>
                                    <td className="p-2">User</td>
                                    <td className="p-2">Role</td>
                                </tr>
                            </thead>
                            <tbody>
                                {step.sqliDbResult?.map((row, i) => (
                                    <tr key={i} className="border-b border-slate-100 odd:bg-slate-50 animate-in fade-in slide-in-from-bottom-2 duration-300" style={{ animationDelay: `${i * 100}ms` }}>
                                        <td className="p-2 text-slate-600">{row.id}</td>
                                        <td className="p-2 font-bold">{row.user}</td>
                                        <td className="p-2">
                                            <span className={`px-2 py-0.5 rounded text-xs font-bold text-white ${row.role === 'admin' ? 'bg-red-500' : 'bg-blue-500'}`}>
                                                {row.role.toUpperCase()}
                                            </span>
                                        </td>
                                    </tr>
                                ))}
                                {(!step.sqliDbResult || step.sqliDbResult.length === 0) && (
                                    <tr>
                                        <td colSpan={3} className="p-8 text-center text-slate-400 italic">
                                            Waiting for query execution...
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

    </div>
  );
};
