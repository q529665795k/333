 // Mail Sender Worker — 基于 Resend 邮件 API
// 域名: 808.qzz.io | 发件: q@808.qzz.io
// 安全加固: 方法限制 / 频率限制 / 爬虫拦截 / 注入检测
// 管理员通知: register / online / login
// 全局限量: 100封/天，每日UTC凌晨自动归零
// ============================================================

const ADMIN_EMAIL = 'q@808.qzz.io';
const FROM_EMAIL = 'q@808.qzz.io';
const FROM_NAME = '摸鱼基地';
const GLOBAL_LIMIT = 100;
const globalKey = 'global:mail_count';
const globalDateKey = 'global:mail_date';

function getBeijingTime() {
  const d = new Date();
  const bjTime = new Date(d.getTime() + 8 * 3600 * 1000);
  const year = bjTime.getFullYear();
  const month = String(bjTime.getMonth() + 1).padStart(2, '0');
  const day = String(bjTime.getDate()).padStart(2, '0');
  const hour = String(bjTime.getHours()).padStart(2, '0');
  const min = String(bjTime.getMinutes()).padStart(2, '0');
  return `${year}-${month}-${day} ${hour}:${min}`;
}


// ---------- 验证码 HTML 模板 ----------
function buildVerifyHtml(code) {
  return `<div style="font-family:system-ui,Arial;max-width:480px;margin:0 auto;padding:25px;border:1px solid #eee;border-radius:12px;">
<p style="font-size:16px;color:#333;margin:0 0 15px 0;">亲爱的用户，欢迎您来到摸鱼基地！</p>
<p style="font-size:16px;color:#444;margin:0 0 15px 0;">
本次<strong style="color:#2563eb;font-weight:bold;">摸鱼基地注册验证码</strong>：
<span style="font-size:24px;font-weight:bold;color:#1967d2;">${code}</span>，
有效期60秒，超时将自动失效，请勿转发他人。
</p>
<p style="font-size:15px;color:#555;margin:0;">基地官网：
<a href="https://808.qzz.io" style="color:#2563eb;text-decoration:none;font-weight:bold;" target="_blank">https://808.qzz.io</a>
</p>
</div>`;
}

// ---------- 管理员通知 HTML 模板 ----------
function buildAdminHtml(type, to, ip, location) {
  const typeMap = {
    register: { title: '🆕 新用户注册提醒', color: '#2563eb' },
    online:   { title: '🟢 用户上线提醒', color: '#16a34a' },
    login:    { title: '🔴 频繁异地登录告警', color: '#dc2626' },
  };
  const cfg = typeMap[type] || { title: '📢 系统通知', color: '#333' };
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

  return `<div style="font-family:system-ui,Arial;max-width:520px;margin:0 auto;padding:25px;border:1px solid #eee;border-radius:12px;">
<h2 style="font-size:18px;color:${cfg.color};margin:0 0 18px 0;">${cfg.title}</h2>
<table style="width:100%;font-size:15px;color:#444;border-collapse:collapse;">
<tr><td style="padding:6px 12px;font-weight:bold;color:#555;width:90px;">用户邮箱</td><td style="padding:6px 12px;">${to}</td></tr>
<tr><td style="padding:6px 12px;font-weight:bold;color:#555;">IP 地址</td><td style="padding:6px 12px;">${ip || '未知'}</td></tr>
<tr><td style="padding:6px 12px;font-weight:bold;color:#555;">所在地区</td><td style="padding:6px 12px;">${location || '未知'}</td></tr>
<tr><td style="padding:6px 12px;font-weight:bold;color:#555;">事件时间</td><td style="padding:6px 12px;">${now}</td></tr>
</table>
<p style="font-size:13px;color:#999;margin:18px 0 0 0;">— 摸鱼基地系统自动通知，请勿回复</p>
</div>`;
}

// ---------- Resend 发信 ----------
async function sendViaResend(env, { to, subject, html, text }) {
  const payload = {
    from: `${FROM_NAME} <${FROM_EMAIL}>`,
    to: [to],
    subject,
    html,
    text: text || html.replace(/<[^>]*>/g, ''),
  };

  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
    },
    body: JSON.stringify(payload),
  });

  const respText = await resp.text();
  if (!resp.ok) {
    throw new Error(`Resend error: ${resp.status} — ${respText}`);
  }
  return respText;
}

// ---------- 主处理 ----------
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
    const botPatterns = ['nikto','nmap','masscan','zgrab','dirbuster','sqlmap','wpscan','acunetix'];
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

    // ---------- 3.5 全局限量 (100封/天，每日UTC凌晨自动归零) ----------
    const today = getTodayUTC();
    let mailCount = 0;
    let savedDate = '';

    try {
      const rawCount = await env.MAIL_KV.get(globalKey);
      const rawDate = await env.MAIL_KV.get(globalDateKey);
      if (rawCount) mailCount = parseInt(rawCount, 10) || 0;
      if (rawDate) savedDate = rawDate;
    } catch (_) { /* miss → 0 */ }

    if (savedDate !== today) {
      mailCount = 0;
      await env.MAIL_KV.put(globalDateKey, today);
      await env.MAIL_KV.put(globalKey, '0');
    }

    if (mailCount >= GLOBAL_LIMIT) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Daily mail limit reached (100)',
        remaining: 0
      }), {
        status: 429,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // ---------- 4. 解析 & 校验参数 ----------
    let body;
    try {
      body = await request.json();
    } catch {
      return new Response(JSON.stringify({ success: false, error: 'Invalid JSON body' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    const { to, subject, text, code, type, ip, location } = body;

    if (!to || typeof to !== 'string') {
      return new Response(JSON.stringify({ success: false, error: 'to is required' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(to)) {
      return new Response(JSON.stringify({ success: false, error: 'Invalid recipient email' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // ---------- 5. 分流：管理员通知 vs 用户验证码 ----------
    const validTypes = ['register', 'online', 'login'];

    if (type && validTypes.includes(type)) {
      // ====== 管理员通知邮件 ======
      const typeLabel = { register: '新用户注册', online: '用户上线', login: '异地登录告警' };
      const adminSubject = `[${typeLabel[type]}] ${to}`;

      const html = buildAdminHtml(type, to, ip, location);
      try {
        await sendViaResend(env, { to: ADMIN_EMAIL, subject: adminSubject, html });
        mailCount += 1;
        await env.MAIL_KV.put(globalKey, String(mailCount));
        return new Response(JSON.stringify({
          success: true,
          message: 'Admin notification sent',
          remaining: GLOBAL_LIMIT - mailCount
        }), {
          status: 200, headers: { 'Content-Type': 'application/json' }
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: 'Admin notify failed', detail: err.message }), {
          status: 502, headers: { 'Content-Type': 'application/json' }
        });
      }

    } else {
      // ====== 用户验证码邮件 ======
      if (!code || typeof code !== 'string') {
        return new Response(JSON.stringify({ success: false, error: 'code is required for verification email' }), {
          status: 400, headers: { 'Content-Type': 'application/json' }
        });
      }

      const injectionPatterns = [
        /<script/i, /javascript:/i, /on\w+\s*=/i,
        /\bcc:\s*/i, /\bbcc:\s*/i, /\bto:\s*/i,
        /\r\n/i, /\0/
      ];
      const hasInjection = (str) => injectionPatterns.some(p => p.test(str));
      if (subject && hasInjection(subject)) {
        return new Response(JSON.stringify({ success: false, error: 'Content contains disallowed patterns' }), {
          status: 400, headers: { 'Content-Type': 'application/json' }
        });
      }

      const emailSubject = subject || '摸鱼基地验证码';
      if (emailSubject.length > 200) {
        return new Response(JSON.stringify({ success: false, error: 'Subject too long (max 200)' }), {
          status: 400, headers: { 'Content-Type': 'application/json' }
        });
      }

      const html = buildVerifyHtml(code);
      const plainText = `您的摸鱼基地验证码为：${code}，有效期60秒，请勿转发他人。`;

      try {
        await sendViaResend(env, { to, subject: emailSubject, html, text: plainText });
        mailCount += 1;
        await env.MAIL_KV.put(globalKey, String(mailCount));
        return new Response(JSON.stringify({
          success: true,
          message: 'Verification email sent',
          remaining: GLOBAL_LIMIT - mailCount
        }), {
          status: 200, headers: { 'Content-Type': 'application/json' }
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: 'Send failed', detail: err.message }), {
          status: 502, headers: { 'Content-Type': 'application/json' }
        });
      }
    }
  },
};
