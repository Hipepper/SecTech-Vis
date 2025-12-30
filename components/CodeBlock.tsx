import React from 'react';

interface CodeBlockProps {
  code: string;
  highlightLines: number[];
}

export const CodeBlock: React.FC<CodeBlockProps> = ({ code, highlightLines }) => {
  const lines = code.split('\n');

  return (
    <div className="bg-slate-900 rounded-lg p-4 font-mono text-xs sm:text-sm overflow-x-auto border border-slate-700 shadow-inner">
      <pre>
        {lines.map((line, i) => {
          const lineNumber = i + 1;
          const isHighlighted = highlightLines.includes(lineNumber);
          return (
            <div
              key={i}
              className={`${
                isHighlighted
                  ? 'bg-yellow-500/20 text-yellow-200 border-l-2 border-yellow-500 pl-2'
                  : 'text-slate-400 pl-2.5 border-l-2 border-transparent'
              } transition-colors duration-300 w-full`}
            >
              <span className="inline-block w-6 select-none text-slate-600 mr-2 text-right">
                {lineNumber}
              </span>
              {line}
            </div>
          );
        })}
      </pre>
    </div>
  );
};
