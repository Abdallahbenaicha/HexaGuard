/**
 * Unified Safe Markdown and HTML Sanitization Utility.
 * 
 * Prevents Stored and Reflected XSS by contextually escaping raw HTML entities
 * before applying Markdown formatting transformations.
 */

export function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

export function encodeCode(str) {
    try {
        return btoa(unescape(encodeURIComponent(str)));
    } catch {
        return btoa(str);
    }
}

export function renderMarkdown(text) {
    if (!text) return '';

    // Step 1: Escape untrusted HTML tags and attributes
    const escaped = escapeHtml(text);

    // Step 2: Safely apply Markdown transformations over the escaped text
    return escaped
        .replace(/^### (.+)$/gm, '<h3 class="text-primary-600 dark:text-primary-400 font-bold text-sm mt-3 mb-1">$1</h3>')
        .replace(/^## (.+)$/gm,  '<h2 class="text-slate-800 dark:text-slate-100 font-bold text-sm mt-4 mb-1">$1</h2>')
        .replace(/^# (.+)$/gm,   '<h1 class="text-slate-900 dark:text-white font-bold text-base mt-4 mb-2">$1</h1>')
        .replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>')
        .replace(/\*\*(.+?)\*\*/g,     '<strong class="font-semibold text-slate-900 dark:text-white">$1</strong>')
        .replace(/\*(.+?)\*/g,         '<em>$1</em>')
        .replace(/`([^`\n]+)`/g, '<code class="bg-slate-100 dark:bg-slate-800 text-primary-600 dark:text-primary-400 px-1.5 py-0.5 rounded-md font-mono text-[11px] border border-slate-200 dark:border-slate-700">$1</code>')
        .replace(/^---$/gm, '<hr class="border-slate-200 dark:border-slate-700 my-3" />')
        .replace(/^[•-] (.+)$/gm, '<div class="flex gap-2 my-0.5"><span class="text-primary-500 font-bold flex-shrink-0 mt-0.5">▸</span><span>$1</span></div>')
        .replace(/^\d+\. (.+)$/gm, '<div class="flex gap-2 my-0.5"><span class="text-primary-500 font-bold flex-shrink-0">›</span><span>$1</span></div>')
        .replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
            const encoded = encodeCode(code.trim());
            return `<div class="my-3 rounded-xl overflow-hidden border border-slate-200 dark:border-slate-700">
              <div class="flex items-center justify-between bg-slate-100 dark:bg-slate-800 px-3 py-1.5 border-b border-slate-200 dark:border-slate-700">
                <span class="text-[10px] text-slate-500 dark:text-slate-400 font-mono uppercase tracking-wider">${lang || 'code'}</span>
                <button data-copy="${encoded}" class="copy-btn text-[10px] text-slate-500 hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400 font-medium transition-colors px-2 py-0.5 rounded hover:bg-slate-200 dark:hover:bg-slate-700">Copy</button>
              </div>
              <pre class="bg-slate-950 p-4 text-[11px] text-emerald-400 font-mono overflow-x-auto leading-relaxed">${code.trim()}</pre>
            </div>`;
        })
        .replace(/\n/g, '<br />');
}
