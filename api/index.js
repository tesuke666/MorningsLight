// api/relay.js - Edge Runtime Relay for Vercel
//完全オリジナル実装 - 非XHTTPコピー

/**
 * 環境変数:
 * - RELAY_SECRET   : اختیاری - برای احراز هویت (از طریق هدر X-Relay-Secret یا پارامتر ?key=)
 * - BACKEND_URL    : اجباری - آدرس سرور پشتیبان شما (مثلاً https://my-v2ray-server.com)
 * - RELAY_PREFIX   : اختیاری - پیشوند مسیر رله (پیش‌فرض 'relay')
 * 
 * مسیر نمونه: https://your-project.vercel.app/relay/api/v1/ → به backend ارسال می‌شود.
 */

export const config = { runtime: 'edge' };

// ----- پیکربندی اولیه از متغیرهای محیطی -----
const BACKEND_URL = process.env.BACKEND_URL;
const RELAY_SECRET = process.env.RELAY_SECRET || '';
const RELAY_PREFIX = (process.env.RELAY_PREFIX || 'relay').replace(/^\/+|\/+$/g, '');

// ----- توابع کمکی -----
function unauthorized(message = 'Unauthorized') {
  return new Response(JSON.stringify({ error: message }), {
    status: 401,
    headers: { 'Content-Type': 'application/json' }
  });
}

function badRequest(message = 'Bad Request') {
  return new Response(JSON.stringify({ error: message }), {
    status: 400,
    headers: { 'Content-Type': 'application/json' }
  });
}

function internalError(message = 'Internal Server Error') {
  return new Response(JSON.stringify({ error: message }), {
    status: 500,
    headers: { 'Content-Type': 'application/json' }
  });
}

// حذف هدرهای hop-by-hop که نباید پراکسی شوند
function filterHeaders(headers) {
  const hopByHop = [
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade', 'content-length'
  ];
  const newHeaders = new Headers();
  for (const [key, value] of headers.entries()) {
    if (!hopByHop.includes(key.toLowerCase())) {
      newHeaders.set(key, value);
    }
  }
  return newHeaders;
}

// بررسی احراز هویت (هدر سفارشی یا کوئری `key`)
function isAuthenticated(request) {
  if (!RELAY_SECRET) return true; // اگر سکرت تنظیم نشده، همه مجازند
  
  // چک هدر X-Relay-Secret
  const headerAuth = request.headers.get('X-Relay-Secret');
  if (headerAuth === RELAY_SECRET) return true;
  
  // چک پارامتر `key` در URL
  const url = new URL(request.url);
  const queryKey = url.searchParams.get('key');
  if (queryKey === RELAY_SECRET) return true;
  
  return false;
}

// ----- هندلر اصلی -----
export default async function handler(request) {
  try {
    // 1. بررسی وجود BACKEND_URL
    if (!BACKEND_URL) {
      console.error('BACKEND_URL environment variable is not set.');
      return internalError('Backend URL not configured.');
    }

    const url = new URL(request.url);
    const pathParts = url.pathname.split('/').filter(p => p);
    
    // 2. بررسی پیشوند مسیر (مثلاً /relay/...)
    if (pathParts[0] !== RELAY_PREFIX) {
      // اگر درخواست به این مسیر نباشد، بگذارید پروژه اصلی پاسخ دهد
      // برای این کار در vercel.json باید یک fallback داشته باشیم.
      return new Response('Not Found', { status: 404 });
    }

    // 3. احراز هویت
    if (!isAuthenticated(request)) {
      return unauthorized('Invalid or missing relay secret.');
    }

    // 4. ساخت URL مقصد
    // حذف پیشوند رله از مسیر: /relay/api/users → /api/users
    const remainingPath = '/' + pathParts.slice(1).join('/');
    const targetUrl = new URL(remainingPath, BACKEND_URL);
    
    // حفظ کوئری استرینگ اصلی (به جز پارامتر key که فقط برای احراز بود)
    if (url.search) {
      const searchParams = new URLSearchParams(url.search);
      searchParams.delete('key'); // حذف key قبل از ارسال به بک‌اند
      targetUrl.search = searchParams.toString();
    }

    // 5. کپی هدرهای مجاز
    const filteredHeaders = filterHeaders(request.headers);
    // اضافه کردن هدر X-Forwarded-For (اختیاری)
    const clientIp = request.headers.get('cf-connecting-ip') || 
                     request.headers.get('x-forwarded-for') || 
                     'unknown';
    filteredHeaders.set('X-Forwarded-For', clientIp);
    // حذف Host اصلی (اجباراً Host مقصد را می‌گذاریم)
    filteredHeaders.set('Host', targetUrl.host);

    // 6. ارسال درخواست به بک‌اند
    const fetchInit = {
      method: request.method,
      headers: filteredHeaders,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      redirect: 'follow'  // اجازه ریدایرکت
    };

    const response = await fetch(targetUrl.toString(), fetchInit);

    // 7. ساخت پاسخ برای کلاینت
    const responseHeaders = new Headers();
    for (const [key, value] of response.headers.entries()) {
      // فیلتر هدرهای hop-by-hop در پاسخ هم
      if (!['connection', 'keep-alive', 'transfer-encoding', 'upgrade'].includes(key.toLowerCase())) {
        responseHeaders.set(key, value);
      }
    }
    // اضافه کردن هدر نشان‌دهنده اینکه از رله عبور کرده
    responseHeaders.set('X-Relayed-By', 'EdgeRelay/1.0');

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });

  } catch (err) {
    console.error('Relay error:', err);
    return internalError('Relay failed: ' + err.message);
  }
}
