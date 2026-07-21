import { useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, Bot, ImagePlus, Loader2, Send, Trash2, X } from 'lucide-react';
import api from '../services/api';
import toast from 'react-hot-toast';

const STORAGE_KEY = 'ng_assistant_history';
const DIRECT_IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/heic', 'image/heif']);
const WELCOME = {
  role: 'assistant',
  text: 'Hi! I am your NetGuard security assistant. Ask me about a finding, or attach a redacted screenshot and I will guide you step by step.',
};

function readDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error('Could not read image'));
    reader.readAsDataURL(file);
  });
}

function canvasBlob(canvas, type, quality) {
  return new Promise((resolve) => canvas.toBlob(resolve, type, quality));
}

async function prepareImage(file) {
  if (!file.type.startsWith('image/')) throw new Error('Select an image file');
  if (file.size > 8 * 1024 * 1024) throw new Error('Images must be 8 MB or smaller before conversion');

  // Gemini accepts HEIC/HEIF directly even when the browser cannot decode them.
  if (['image/heic', 'image/heif'].includes(file.type)) {
    if (file.size > 4 * 1024 * 1024) throw new Error('HEIC/HEIF images must be 4 MB or smaller');
    const dataUrl = await readDataUrl(file);
    return { mimeType: file.type, data: dataUrl.split(',')[1], name: file.name };
  }

  try {
    const bitmap = await createImageBitmap(file);
    const scale = Math.min(1, 1800 / Math.max(bitmap.width, bitmap.height));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    const context = canvas.getContext('2d', { alpha: false });
    context.fillStyle = '#ffffff';
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    bitmap.close();

    const preferredType = file.type === 'image/png' ? 'image/png' : 'image/jpeg';
    let blob = await canvasBlob(canvas, preferredType, 0.9);
    if (!blob || blob.size > 4 * 1024 * 1024) blob = await canvasBlob(canvas, 'image/jpeg', 0.82);
    if (!blob || blob.size > 4 * 1024 * 1024) throw new Error('Converted image is still too large');
    const dataUrl = await readDataUrl(blob);
    return { mimeType: blob.type, data: dataUrl.split(',')[1], name: file.name };
  } catch (error) {
    // If conversion is unavailable, supported Gemini formats can still be sent directly.
    if (DIRECT_IMAGE_TYPES.has(file.type) && file.size <= 4 * 1024 * 1024) {
      const dataUrl = await readDataUrl(file);
      return { mimeType: file.type, data: dataUrl.split(',')[1], name: file.name };
    }
    throw new Error('Use PNG, JPEG, WebP, HEIC, HEIF, or another browser-readable image');
  }
}

function loadStoredMessages() {
  try {
    const stored = JSON.parse(sessionStorage.getItem(STORAGE_KEY));
    return Array.isArray(stored) && stored.length ? stored.slice(-20) : [WELCOME];
  } catch {
    return [WELCOME];
  }
}

export default function SecurityAssistant() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState(loadStoredMessages);
  const [input, setInput] = useState('');
  const [image, setImage] = useState(null);
  const [issue, setIssue] = useState('');
  const [sending, setSending] = useState(false);
  const [proactive, setProactive] = useState(null);
  const bottomRef = useRef(null);
  const fileRef = useRef(null);

  useEffect(() => {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(messages.slice(-20)));
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, open]);

  useEffect(() => {
    Promise.all([
      api.get('/api/dashboard/overview'),
      api.get('/api/dashboard/sites'),
    ]).then(([overviewResponse, sitesResponse]) => {
      const findings = overviewResponse.data?.data?.recentThreats || [];
      const sites = sitesResponse.data?.data || [];
      const websiteIssue = sites.find((site) => (site.counters?.blocked || 0) > 0 || (site.counters?.recaptchaFailed || 0) > 0 || site.integrationStatus === 'offline');
      if (websiteIssue) {
        const blocked = websiteIssue.counters?.blocked || 0;
        const failed = websiteIssue.counters?.recaptchaFailed || 0;
        const issue = websiteIssue.integrationStatus === 'offline'
          ? `${websiteIssue.siteName} integration is offline and has not sent a recent heartbeat.`
          : `${websiteIssue.siteName} has ${blocked} temporary block(s) and ${failed} failed reCAPTCHA verification(s).`;
        setProactive({
          text: `I found a protected-website issue on ${websiteIssue.siteName}. If you want to fix it, I can guide you.`,
          issue,
        });
      } else if (findings.length) {
        const latest = findings[0];
        setProactive({
          text: `I found ${findings.length} recent browser security issue${findings.length === 1 ? '' : 's'}. If you want to fix ${findings.length === 1 ? 'it' : 'them'}, I can guide you.`,
          issue: `${latest.severity || 'medium'} ${latest.category}: ${latest.detail}`,
        });
      }
    }).catch(() => {});

    const handleOpen = (event) => {
      const nextIssue = String(event.detail?.issue || 'Review my latest security findings and guide me through the safest fixes.');
      setIssue(nextIssue);
      setInput(`Please guide me through fixing this issue: ${nextIssue}`);
      setOpen(true);
      setProactive(null);
    };
    window.addEventListener('netguard:assistant', handleOpen);
    return () => window.removeEventListener('netguard:assistant', handleOpen);
  }, []);

  const historyForApi = useMemo(() => messages.slice(-10).map((message) => ({
    role: message.role,
    text: message.text,
  })), [messages]);

  const handleImage = async (event) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    try {
      const prepared = await prepareImage(file);
      setImage(prepared);
      toast.success('Image ready. Make sure all secrets are redacted.');
    } catch (error) {
      toast.error(error.message);
    }
  };

  const send = async () => {
    const text = input.trim();
    if ((!text && !image) || sending) return;
    const userMessage = { role: 'user', text: text || `Analyze attached image: ${image.name}`, imageName: image?.name };
    setMessages((current) => [...current, userMessage]);
    setInput('');
    setSending(true);
    try {
      const response = await api.post('/api/assistant/chat', {
        message: text,
        image: image ? { mimeType: image.mimeType, data: image.data } : null,
        history: historyForApi,
        context: { route: window.location.pathname, issue },
      });
      setMessages((current) => [...current, { role: 'assistant', text: response.data.data.reply }]);
      setImage(null);
    } catch (error) {
      const message = error.response?.data?.message || 'Assistant request failed. Please try again.';
      setMessages((current) => [...current, { role: 'assistant', text: `I could not answer: ${message}` }]);
    } finally {
      setSending(false);
    }
  };

  const clearChat = () => {
    setMessages([WELCOME]);
    setImage(null);
    setIssue('');
    sessionStorage.removeItem(STORAGE_KEY);
  };

  return (
    <>
      {!open && proactive && (
        <button onClick={() => {
          setIssue(proactive.issue);
          setInput(`Help me fix this finding: ${proactive.issue}`);
          setOpen(true);
          setProactive(null);
        }} className="fixed right-6 bottom-24 z-50 w-80 text-left card p-4 shadow-2xl border-warning/30 bg-card hover:border-warning transition-all">
          <div className="flex gap-3"><AlertTriangle className="w-5 h-5 text-warning shrink-0" /><p className="text-sm text-gray-300">{proactive.text}</p></div>
        </button>
      )}

      {!open && (
        <button onClick={() => setOpen(true)} aria-label="Open NetGuard Assistant" className="fixed right-6 bottom-6 z-50 w-14 h-14 rounded-full bg-primary hover:bg-blue-600 text-white shadow-xl shadow-primary/30 flex items-center justify-center transition-transform hover:scale-105">
          <Bot className="w-7 h-7" />
        </button>
      )}

      {open && (
        <section className="fixed right-6 bottom-6 z-50 w-[min(420px,calc(100vw-2rem))] h-[min(680px,calc(100vh-2rem))] bg-card border border-border rounded-2xl shadow-2xl flex flex-col overflow-hidden">
          <header className="p-4 border-b border-border bg-surface flex items-center justify-between">
            <div className="flex items-center gap-3"><div className="w-9 h-9 rounded-lg bg-primary/15 flex items-center justify-center"><Bot className="w-5 h-5 text-primary" /></div><div><h2 className="font-semibold text-gray-100">NetGuard Assistant</h2><p className="text-xs text-safe">Gemini security guidance</p></div></div>
            <div className="flex items-center gap-1"><button onClick={clearChat} title="Clear chat" className="p-2 text-gray-500 hover:text-danger"><Trash2 className="w-4 h-4" /></button><button onClick={() => setOpen(false)} title="Close" className="p-2 text-gray-500 hover:text-gray-200"><X className="w-5 h-5" /></button></div>
          </header>

          <div className="px-4 py-2 bg-warning/5 border-b border-warning/10 text-[11px] text-warning">Messages/images are sent to Google Gemini. Redact passwords, API keys, tokens, cookies, database URLs, and personal information first.</div>

          <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {messages.map((message, index) => (
              <div key={`${message.role}-${index}`} className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[88%] rounded-xl px-3.5 py-2.5 text-sm whitespace-pre-wrap break-words ${message.role === 'user' ? 'bg-primary text-white' : 'bg-surface border border-border text-gray-300'}`}>
                  {message.imageName && <div className="text-xs opacity-75 mb-1">📎 {message.imageName}</div>}
                  {message.text}
                </div>
              </div>
            ))}
            {sending && <div className="flex items-center gap-2 text-sm text-gray-500"><Loader2 className="w-4 h-4 animate-spin" /> Analyzing securely…</div>}
            <div ref={bottomRef} />
          </div>

          {image && <div className="mx-4 mb-2 p-2 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-between text-xs text-primary"><span className="truncate">Image: {image.name}</span><button onClick={() => setImage(null)}><X className="w-4 h-4" /></button></div>}

          <footer className="p-3 border-t border-border bg-surface">
            <div className="flex items-end gap-2">
              <input ref={fileRef} type="file" accept="image/*,.heic,.heif" onChange={handleImage} className="hidden" />
              <button onClick={() => fileRef.current?.click()} title="Attach image" className="p-2.5 rounded-lg border border-border text-gray-400 hover:text-primary hover:border-primary/40"><ImagePlus className="w-5 h-5" /></button>
              <textarea value={input} onChange={(event) => setInput(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); send(); } }} rows={2} maxLength={4000} placeholder="Ask how to fix an issue…" className="input-field flex-1 resize-none text-sm" />
              <button onClick={send} disabled={sending || (!input.trim() && !image)} className="p-2.5 rounded-lg bg-primary text-white disabled:opacity-40"><Send className="w-5 h-5" /></button>
            </div>
          </footer>
        </section>
      )}
    </>
  );
}
