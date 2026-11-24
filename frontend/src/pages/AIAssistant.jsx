import React, { useState, useEffect, useRef } from 'react';
import { 
  Bot, 
  Send, 
  Sparkles, 
  ShieldCheck, 
  Terminal, 
  HelpCircle, 
  Copy, 
  Check, 
  CornerDownLeft,
  BookOpen
} from 'lucide-react';
import scanService from '../services/api';

const QUICK_PROMPTS = [
  'What is an SSL certificate and why is it important?',
  'Why does my site need a Content-Security-Policy (CSP)?',
  'What does Cross-Site Scripting (XSS) mean?',
  'How do I fix missing X-Frame-Options against Clickjacking?',
  'What is SQL Injection and how do I prevent it?',
  'Explain my latest website scan results',
];

export const AIAssistant = ({ initialScanId }) => {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content:
        'Hello! I am **SecureExplain AI Assistant**.\n\nI can help you understand website vulnerabilities, explain complex cybersecurity concepts in simple English, and give you copy-paste configuration fixes for Nginx, Apache, or Node.js.\n\nWhat would you like to explore today?',
    },
  ]);
  const [inputValue, setInputValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(initialScanId || '');
  const [copiedIndex, setCopiedIndex] = useState(null);
  const chatEndRef = useRef(null);

  useEffect(() => {
    loadScans();
  }, []);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const loadScans = async () => {
    try {
      const data = await scanService.getScans();
      setScans(data);
      if (!selectedScanId && data.length > 0) {
        setSelectedScanId(data[0].scan_id);
      }
    } catch (err) {
      console.error('Failed to load scans for assistant context:', err);
    }
  };

  const handleSendMessage = async (textToSend) => {
    const text = textToSend || inputValue;
    if (!text.trim() || loading) return;

    const userMessage = { role: 'user', content: text };
    setMessages((prev) => [...prev, userMessage]);
    setInputValue('');
    setLoading(true);

    try {
      const response = await scanService.chatWithAssistant(
        text,
        'chat-session-1',
        selectedScanId || null
      );
      setMessages((prev) => [...prev, { role: 'assistant', content: response.content }]);
    } catch (err) {
      console.error('Chat error:', err);
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: 'I encountered an error connecting to the AI explainer service. Please verify backend status.',
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleCopyMessage = (content, index) => {
    navigator.clipboard.writeText(content);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="space-y-4 max-w-5xl mx-auto h-[calc(100vh-8rem)] flex flex-col">
      {/* Top Banner & Context Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3 shrink-0">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <Bot className="h-6 w-6 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white flex items-center gap-2">
              <span>AI Cybersecurity Assistant</span>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                Gemini Powered
              </span>
            </h1>
            <p className="text-xs text-slate-400">Ask any cybersecurity question or get personalized scan remediations.</p>
          </div>
        </div>

        {/* Scan Context Selector */}
        {scans.length > 0 && (
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400 font-semibold">Active Scan Context:</span>
            <select
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-cyan-300 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="">None (General Cyber Advice)</option>
              {scans.map((s) => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.target_domain} (Score: {s.security_score})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Messages Thread Container */}
      <div className="flex-1 overflow-y-auto space-y-4 pr-2">
        {messages.map((msg, idx) => {
          const isUser = msg.role === 'user';

          return (
            <div
              key={idx}
              className={`flex gap-3 ${isUser ? 'justify-end' : 'justify-start'}`}
            >
              {!isUser && (
                <div className="h-8 w-8 rounded-lg bg-indigo-600/30 border border-indigo-500/40 flex items-center justify-center shrink-0 text-indigo-300">
                  <Sparkles className="h-4 w-4" />
                </div>
              )}

              <div
                className={`max-w-[85%] rounded-2xl p-4 text-xs leading-relaxed shadow-lg ${
                  isUser
                    ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-medium'
                    : 'bg-[#0d1424] border border-slate-800 text-slate-200'
                }`}
              >
                <div className="whitespace-pre-line prose-invert font-sans">
                  {msg.content}
                </div>

                {!isUser && (
                  <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-end">
                    <button
                      onClick={() => handleCopyMessage(msg.content, idx)}
                      className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-cyan-300 transition"
                    >
                      {copiedIndex === idx ? (
                        <>
                          <Check className="h-3 w-3 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" />
                          <span>Copy Response</span>
                        </>
                      )}
                    </button>
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {loading && (
          <div className="flex gap-3 justify-start">
            <div className="h-8 w-8 rounded-lg bg-indigo-600/30 border border-indigo-500/40 flex items-center justify-center shrink-0 text-indigo-300">
              <Sparkles className="h-4 w-4 animate-spin" />
            </div>
            <div className="rounded-2xl bg-[#0d1424] border border-slate-800 p-4 text-xs text-slate-400 flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
              <span>Analyzing security question with Generative AI...</span>
            </div>
          </div>
        )}

        <div ref={chatEndRef} />
      </div>

      {/* Suggested Quick Prompts */}
      <div className="shrink-0 flex items-center gap-2 overflow-x-auto pb-1">
        <span className="text-[11px] font-semibold text-slate-500 uppercase shrink-0">Quick Topics:</span>
        {QUICK_PROMPTS.map((prompt, i) => (
          <button
            key={i}
            onClick={() => handleSendMessage(prompt)}
            disabled={loading}
            className="shrink-0 px-3 py-1 rounded-full border border-slate-800 bg-slate-900/60 hover:bg-slate-800 hover:border-cyan-500/50 text-[11px] text-slate-300 transition"
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* Input Box */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSendMessage();
        }}
        className="shrink-0 relative flex items-center rounded-xl border border-slate-700 bg-[#0c1322] p-1.5 focus-within:border-cyan-500"
      >
        <input
          type="text"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          placeholder="Ask a cybersecurity question, request configuration snippets, or inquire about scan findings..."
          className="flex-1 bg-transparent px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none"
          disabled={loading}
        />
        <button
          type="submit"
          disabled={loading || !inputValue.trim()}
          className="cyber-button-gradient flex h-8 w-8 items-center justify-center rounded-lg text-white disabled:opacity-50 transition"
        >
          <Send className="h-4 w-4" />
        </button>
      </form>
    </div>
  );
};

export default AIAssistant;
