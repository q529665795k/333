// ============================================================
// Mail Sender Worker — 基于 MailChannels 免费邮件 API
// 域名: 808.qzz.io | 发件: q@808.qzz.io
// 安全加固: 方法限制 / 频率限制 / 爬虫拦截 / 注入检测
// ============================================================

export default {
  async fetch(request, env, ctx) {
    // ---------- 1. 仅放行 POST ----------
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ success: false, error: 'Method Not Allowed' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json', 'Allow': 'POST' },
      });
    }

    // ---------- 2. 拦截爬虫 / 异常代理 / 高危特征 ----------
    const ua = (request.headers.get('User-Agent') || '').toLowerCase();
    const botPatterns = [
      'bot', 'crawler', 'spider', 'scan', 'curl/', 'wget/',
      'python-requests', 'httpclient', 'go-http', 'java/',
      'nikto', 'nmap', 'masscan', 'zgrab'
    ];
    if (botPatterns.some(p => ua.includes(p))) {
      return new Response(JSON.stringify({ success: false, error: 'Forbidden' }), {
        status: 403, headers: { 'Content-Type': 'application/json' }
      });
    }

    const viaHeader = request.headers.get('Via') || '';
    if (viaHeader && viaHeader.split(',').length > 3) {
      return new Response(JSON.stringify({ success: false, error: 'Forbidden' }), {
        status: 403, headers: { 'Content-Type': 'application/json' }
      });
    }

    // ---------- 3. 频率限制 (IP + KV, 每小时10次) ----------
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rateKey = 'rate:' + clientIP;
    const MAX_PER_HOUR = 10;
    let rateRecord = { count: 0, ts: Date.now() };

    try {
      const raw = await env.MAIL_KV.get(rateKey);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Date.now() - parsed.ts < 3600000) rateRecord = parsed;
      }
    } catch (_) { /* KV miss → reset */ }

    if (rateRecord.count >= MAX_PER_HOUR) {
      return new Response(JSON.stringify({ success: false, error: 'Rate limit exceeded, try later' }), {
        status: 429,
        headers: { 'Content-Type': 'application/json', 'Retry-After': '3600' },
      });
    }
    rateRecord.count += 1;
    await env.MAIL_KV.put(rateKey, JSON.stringify(rateRecord), { expirationTtl: 3600 });

    // ---------- 4. 解析 & 校验参数 ----------
    let body;
    try {
      body = await request.json();
    } catch {
      return new Response(JSON.stringify({ success: false, error: 'Invalid JSON body' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    const { to, subject, text } = body;
    const errors = [];
    if (!to || typeof to !== 'string') errors.push('to is required');
    if (!subject || typeof subject !== 'string') errors.push('subject is required');
    if (!text || typeof text !== 'string') errors.push('text is required');
    if (errors.length) {
      return new Response(JSON.stringify({ success: false, error: errors.join('; ') }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // 邮箱格式
    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(to)) {
      return new Response(JSON.stringify({ success: false, error: 'Invalid recipient email' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // 注入 / 恶意特征检测
    const injectionPatterns = [
      /<script/i, /javascript:/i, /on\w+\s*=/i,
      /\bcc:\s*/i, /\bbcc:\s*/i, /\bto:\s*/i,
      /\r\n/i, /\0/
    ];
    const hasInjection = (str) => injectionPatterns.some(p => p.test(str));
    if (hasInjection(subject) || hasInjection(text)) {
      return new Response(JSON.stringify({ success: false, error: 'Content contains disallowed patterns' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // 长度限制
    if (subject.length > 200) {
      return new Response(JSON.stringify({ success: false, error: 'Subject too long (max 200)' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }
    if (text.length > 10000) {
      return new Response(JSON.stringify({ success: false, error: 'Body too long (max 10000)' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // ---------- 5. 调用 MailChannels 发信 ----------
    const sendPayload = {
      personalizations: [{ to: [{ email: to }] }],
      from: { email: 'q@808.qzz.io', name: '808 Mail' },
      subject,
      content: [{ type: 'text/plain', value: text }],
    };

    try {
      const resp = await fetch('https://api.mailchannels.net/tx/v1/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sendPayload),
      });

      const respText = await resp.text();
      if (!resp.ok) {
        return new Response(JSON.stringify({ success: false, error: 'MailChannels error', detail: respText }), {
          status: 502, headers: { 'Content-Type': 'application/json' }
        });
      }
      return new Response(JSON.stringify({ success: true, message: 'Email sent' }), {
        status: 200, headers: { 'Content-Type': 'application/json' }
      });
    } catch (err) {
      return new Response(JSON.stringify({ success: false, error: 'Send failed', detail: err.message }), {
        status: 500, headers: { 'Content-Type': 'application/json' }
      });
    }
  },
};
