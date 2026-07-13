const express = require('express');
const rateLimit = require('express-rate-limit');
const Threat = require('../models/Threat');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

const SUPPORTED_IMAGE_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/webp',
  'image/heic',
  'image/heif',
]);

const assistantLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { success: false, message: 'Assistant limit reached. Please wait a few minutes and try again.' },
});

function cleanText(value, maxLength) {
  return String(value || '').replace(/\u0000/g, '').trim().slice(0, maxLength);
}

function normalizeImage(value) {
  if (!value || typeof value !== 'object') return null;
  let mimeType = String(value.mimeType || '').toLowerCase();
  let data = String(value.data || '').trim();

  const dataUrl = data.match(/^data:([^;]+);base64,([a-z0-9+/=\r\n]+)$/i);
  if (dataUrl) {
    mimeType = dataUrl[1].toLowerCase();
    data = dataUrl[2];
  }

  if (!SUPPORTED_IMAGE_TYPES.has(mimeType) || !/^[a-z0-9+/=\r\n]+$/i.test(data)) return null;
  const bytes = Buffer.byteLength(data.replace(/\s/g, ''), 'base64');
  if (!bytes || bytes > 4 * 1024 * 1024) return null;
  return { mimeType, data: data.replace(/\s/g, '') };
}

function buildHistory(value) {
  if (!Array.isArray(value)) return [];
  const history = value.slice(-10).map((entry) => ({
    role: entry?.role === 'assistant' ? 'model' : 'user',
    text: cleanText(entry?.text, 2500),
  })).filter((entry) => entry.text);

  while (history.length && history[0].role !== 'user') history.shift();
  return history.map((entry) => ({ role: entry.role, parts: [{ text: entry.text }] }));
}

function issueSummary(threats) {
  if (!threats.length) return 'No recent recorded threats are available for this user.';
  return threats.map((threat, index) => (
    `${index + 1}. ${threat.severity || 'medium'} ${threat.category}: ${cleanText(threat.detail, 240)} on ${threat.domain || 'an unknown domain'}`
  )).join('\n');
}

router.post('/chat', authenticate, assistantLimiter, async (req, res) => {
  try {
    if (!process.env.GEMINI_API_KEY) {
      return res.status(503).json({ success: false, message: 'The security assistant is not configured yet.' });
    }

    const message = cleanText(req.body.message, 4000);
    const image = normalizeImage(req.body.image);
    if (!message && !image) {
      return res.status(400).json({ success: false, message: 'Enter a question or attach a supported image.' });
    }
    if (req.body.image && !image) {
      return res.status(400).json({
        success: false,
        message: 'Use a PNG, JPEG, WebP, HEIC, or HEIF image up to 4 MB.',
      });
    }

    const recentThreats = await Threat.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(5)
      .select('category severity detail domain action createdAt')
      .lean();

    const context = req.body.context && typeof req.body.context === 'object' ? req.body.context : {};
    const route = cleanText(context.route, 120) || '/dashboard';
    const highlightedIssue = cleanText(context.issue, 700);
    const systemInstruction = `You are NetGuard Assistant, a defensive browser and cloud security guide.
Give fast, calm, step-by-step remediation that a non-expert can follow. Continue naturally from prior messages.
When an image is supplied, inspect visible error text and UI state, explain what is visible, and clearly label uncertainty.
Never ask for passwords, API keys, JWTs, database connection strings, cookies, or other secrets. Warn the user to redact them.
Do not provide offensive intrusion, credential theft, malware, evasion, or destructive instructions. You may explain safe defensive testing.
Prefer concise numbered steps, include how to verify the fix, and ask at most one necessary follow-up question.
Current application route: ${route}
Highlighted issue: ${highlightedIssue || 'none'}
Recent user-specific security findings:
${issueSummary(recentThreats)}`;

    const currentParts = [{
      text: message || 'Analyze this screenshot and guide me through fixing the visible issue.',
    }];
    if (image) {
      currentParts.push({ inlineData: { mimeType: image.mimeType, data: image.data } });
    }

    const model = cleanText(process.env.GEMINI_MODEL, 80) || 'gemini-3.5-flash';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 35_000);
    let response;
    try {
      response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-goog-api-key': process.env.GEMINI_API_KEY,
          },
          body: JSON.stringify({
            systemInstruction: { parts: [{ text: systemInstruction }] },
            contents: [...buildHistory(req.body.history), { role: 'user', parts: currentParts }],
            generationConfig: {
              temperature: 0.25,
              maxOutputTokens: 1200,
            },
          }),
          signal: controller.signal,
        }
      );
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      const upstream = await response.json().catch(() => ({}));
      const upstreamMessage = cleanText(upstream?.error?.message, 300);
      console.error('[assistant] Gemini error', response.status, upstreamMessage);
      if (response.status === 429) {
        return res.status(429).json({ success: false, message: 'Gemini free-tier limit reached. Please wait and try again.' });
      }
      return res.status(502).json({ success: false, message: 'The AI service could not answer right now. Please try again.' });
    }

    const result = await response.json();
    const reply = (result.candidates?.[0]?.content?.parts || [])
      .map((part) => part.text || '')
      .join('\n')
      .trim();

    if (!reply) {
      return res.status(502).json({ success: false, message: 'The AI service returned an empty answer. Try rephrasing the question.' });
    }

    res.json({
      success: true,
      data: { reply, model, imageAnalyzed: Boolean(image) },
    });
  } catch (error) {
    const timedOut = error.name === 'AbortError';
    console.error('[assistant]', timedOut ? 'Gemini request timed out' : error.message);
    res.status(timedOut ? 504 : 500).json({
      success: false,
      message: timedOut ? 'The assistant timed out. Please try a shorter question or smaller image.' : 'Assistant request failed.',
    });
  }
});

module.exports = router;
