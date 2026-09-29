/**
 * "Водій" push-worker — мінімальний сервер на Cloudflare Workers, що:
 *  - приймає підписку на push (POST /register) і список найближчих строків
 *  - раз на день (Cron Trigger) перевіряє, що настав час нагадати, і шле Web Push
 *  - дозволяє надіслати тестове сповіщення відразу (POST /test)
 *  - дає адмінці (POST /admin/*) надсилати push усім користувачам і керувати
 *    списком адміністраторів — доступ лише через "Увійти через Google",
 *    без жодних паролів чи додаткових секретів на клієнті.
 *
 * Без жодних npm-залежностей — усе на стандартному Web Crypto API,
 * щоб код можна було вставити напряму в редактор Cloudflare (Quick Edit).
 *
 * Потрібні прив'язки (Settings → Variables and Bindings):
 *   KV namespace: PUSH_KV
 *   Secret vars:  VAPID_PUBLIC_KEY, VAPID_PRIVATE_JWK, VAPID_SUBJECT, APP_SECRET
 *   Cron Trigger: кожні 15 хвилин ("0,15,30,45 * * * *") — щоб заплановані
 *     з адмінки розсилки виходили вчасно; на нагадування про дедлайни це не
 *     впливає, вони й так шлються не частіше раза на день (позначка "notified")
 * Нових прив'язок для адмінки додавати не треба — Google Client ID не є
 * секретом (він вбудований і в сам застосунок, для синхронізації з Google Диском).
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-App-Secret',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

function checkSecret(request, env) {
  if (!env.APP_SECRET) return true; // якщо секрет не налаштовано — пропускаємо перевірку
  return request.headers.get('X-App-Secret') === env.APP_SECRET;
}

// ===== base64url helpers =====
function b64urlToBytes(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function bytesToB64url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function concatBytes(...arrs) {
  const len = arrs.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}
function strToBytes(s) { return new TextEncoder().encode(s); }
function b64urlToString(str) { return new TextDecoder().decode(b64urlToBytes(str)); }

// ===== VAPID JWT (ES256) =====
async function buildVapidHeader(env, audience) {
  const privKey = await crypto.subtle.importKey(
    'jwk', JSON.parse(env.VAPID_PRIVATE_JWK),
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );
  const header = { typ: 'JWT', alg: 'ES256' };
  const now = Math.floor(Date.now() / 1000);
  const payload = { aud: audience, exp: now + 12 * 3600, sub: env.VAPID_SUBJECT || 'https://vova3639.github.io/vodiy-app/' };
  const headerB64 = bytesToB64url(strToBytes(JSON.stringify(header)));
  const payloadB64 = bytesToB64url(strToBytes(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, privKey, strToBytes(signingInput)
  );
  const sigB64 = bytesToB64url(new Uint8Array(sig));
  const jwt = `${signingInput}.${sigB64}`;
  return `vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}`;
}

// ===== Web Push encryption (RFC 8291 aes128gcm) =====
async function sendWebPush(env, subscription, payloadObj) {
  const endpoint = subscription.endpoint;
  const audience = new URL(endpoint).origin;
  const authHeader = await buildVapidHeader(env, audience);

  const uaPublicRaw = b64urlToBytes(subscription.keys.p256dh); // 65 bytes
  const authSecret = b64urlToBytes(subscription.keys.auth);    // 16 bytes

  const uaPublicKey = await crypto.subtle.importKey(
    'raw', uaPublicRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const ephemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );
  const ephemeralPublicRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', ephemeral.publicKey)
  );

  const sharedSecretBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: uaPublicKey }, ephemeral.privateKey, 256
  );
  const sharedSecret = new Uint8Array(sharedSecretBits);

  const keyInfo = concatBytes(
    strToBytes('WebPush: info\0'), uaPublicRaw, ephemeralPublicRaw
  );
  const ecdhSecretKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const ikmBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: authSecret, info: keyInfo }, ecdhSecretKey, 256
  );
  const ikm = new Uint8Array(ikmBits);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const ikmKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const cekBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: strToBytes('Content-Encoding: aes128gcm\0') }, ikmKey, 128
  );
  const nonceBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: strToBytes('Content-Encoding: nonce\0') }, ikmKey, 96
  );
  const cek = new Uint8Array(cekBits);
  const nonce = new Uint8Array(nonceBits);

  const cekKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const plaintext = concatBytes(strToBytes(JSON.stringify(payloadObj)), new Uint8Array([0x02]));
  const cipherBits = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, cekKey, plaintext);
  const ciphertext = new Uint8Array(cipherBits);

  const rs = 4096;
  const rsBytes = new Uint8Array(4);
  new DataView(rsBytes.buffer).setUint32(0, rs, false);
  const header = concatBytes(
    salt, rsBytes, new Uint8Array([ephemeralPublicRaw.length]), ephemeralPublicRaw
  );
  const body = concatBytes(header, ciphertext);

  const resp = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Encoding': 'aes128gcm',
      'TTL': '86400',
      'Authorization': authHeader,
    },
    body,
  });
  return resp;
}

// ===== due-items logic =====
function isDueToday(item) {
  const today = new Date().toISOString().slice(0, 10);
  return item.date && item.date <= today;
}

async function checkAndNotify(env, id, record) {
  const due = (record.items || []).filter(it => isDueToday(it) && !(record.notified || []).includes(it.id));
  if (!due.length) return 0;
  const title = due.length === 1 ? due[0].label : `${due.length} нагадування по «Водій»`;
  const body = due.map(it => it.label + (it.sub ? ' · ' + it.sub : '')).join('\n').slice(0, 500);
  try {
    const resp = await sendWebPush(env, record.subscription, { title, body, tag: 'vodiy-tax' });
    if (resp.status === 404 || resp.status === 410) {
      // підписка більше не дійсна — прибираємо
      await env.PUSH_KV.delete(id);
      await logDeadSubscription(env, id);
      return 0;
    }
  } catch (e) {
    return 0;
  }
  record.notified = [...(record.notified || []), ...due.map(it => it.id)];
  await env.PUSH_KV.put(id, JSON.stringify(record));
  return due.length;
}

// ===== Admin: "Sign in with Google" verification (RS256 ID token) =====
// Той самий публічний Client ID, що вже використовує застосунок для синхронізації
// з Google Диском (не секрет — client id завжди видно в браузері). Авторизовані
// джерела (JS origins) для нього вже включають vova3639.github.io, тож нову
// сторінку адмінки достатньо покласти на той самий домен — окремих
// налаштувань у Google Cloud Console робити не треба.
const ADMIN_GOOGLE_CLIENT_ID = '194714840278-n7imdnf3e9bd0knr8hubq170q5t9unsk.apps.googleusercontent.com';
const ADMIN_KEY = '_admin_emails';
const DEFAULT_ADMIN_EMAIL = 'vova3639@gmail.com';
const TEMPLATES_KEY = '_push_templates';
const HISTORY_KEY = '_push_history';
const SCHEDULED_KEY = '_scheduled_pushes';
const GROWTH_KEY = '_growth_log';
const DEAD_LOG_KEY = '_dead_log';
const FEEDBACK_KEY = '_feedback_log';
const ACTION_LOG_KEY = '_action_log';
const POLLS_KEY = '_polls';
const POLL_VOTES_PREFIX = '_poll_votes_';
const LIVE_SHIFTS_KEY = '_live_shifts';
const BENCHMARK_PREFIX = '_benchmark_';
const DETAILED_STATS_KEY = '_detailed_stats';
const RESERVED_KEYS = [ADMIN_KEY, TEMPLATES_KEY, HISTORY_KEY, SCHEDULED_KEY, GROWTH_KEY, DEAD_LOG_KEY, FEEDBACK_KEY, ACTION_LOG_KEY, POLLS_KEY, LIVE_SHIFTS_KEY, DETAILED_STATS_KEY];
function isReservedKey(name) {
  return RESERVED_KEYS.includes(name) || name.startsWith(POLL_VOTES_PREFIX) || name.startsWith(BENCHMARK_PREFIX);
}

// Куди в застосунку може вести натискання на сповіщення — білий список, щоб
// адмінка не могла надіслати довільний URL. '' означає просто відкрити застосунок.
// Значення — точні назви вкладок/розділів, які розпізнає applyDeepLinkFromHash() в vodiy.html.
// 'poll-<id>' — окремий випадок (опитування), перевіряється форматом, не білим списком.
const DEEP_LINK_TARGETS = new Set([
  '', 'dash', 'shifts', 'expenses', 'cars', 'profile',
  'settings-notifications', 'settings-data', 'settings-about', 'settings-fop', 'settings-reminders'
]);
function isPollTarget(target) { return /^poll-[a-f0-9-]{8,80}$/i.test(String(target || '')); }
function deepLinkToHash(target) {
  if (!target) return './';
  if (DEEP_LINK_TARGETS.has(target) || isPollTarget(target)) return './#' + target;
  return './';
}

// Груба класифікація пристрою за User-Agent — лише для картки "Платформи" в
// адмінці, ні на що інше не впливає.
function classifyPlatform(ua) {
  ua = String(ua || '');
  if (/iPhone|iPad|iPod/i.test(ua)) return 'iOS';
  if (/Android/i.test(ua)) return 'Android';
  if (/Macintosh/i.test(ua)) return 'Mac';
  if (/Windows/i.test(ua)) return 'Windows';
  if (/Linux/i.test(ua)) return 'Linux';
  return 'Інше';
}

let __jwksCache = null, __jwksCacheAt = 0;
async function fetchGoogleJwks() {
  if (__jwksCache && Date.now() - __jwksCacheAt < 3600000) return __jwksCache;
  const resp = await fetch('https://www.googleapis.com/oauth2/v3/certs');
  const data = await resp.json();
  __jwksCache = data.keys || [];
  __jwksCacheAt = Date.now();
  return __jwksCache;
}

async function verifyGoogleIdToken(idToken) {
  if (!idToken || typeof idToken !== 'string' || idToken.split('.').length !== 3) {
    throw new Error('bad-token');
  }
  const [headerB64, payloadB64, sigB64] = idToken.split('.');
  const header = JSON.parse(b64urlToString(headerB64));
  const payload = JSON.parse(b64urlToString(payloadB64));

  const keys = await fetchGoogleJwks();
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error('unknown-key');

  const pubKey = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']
  );
  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5', pubKey, b64urlToBytes(sigB64), strToBytes(`${headerB64}.${payloadB64}`)
  );
  if (!valid) throw new Error('bad-signature');

  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || payload.exp < now) throw new Error('expired');
  if (payload.aud !== ADMIN_GOOGLE_CLIENT_ID) throw new Error('bad-audience');
  if (payload.iss !== 'https://accounts.google.com' && payload.iss !== 'accounts.google.com') throw new Error('bad-issuer');
  if (payload.email_verified !== true && payload.email_verified !== 'true') throw new Error('email-not-verified');
  if (!payload.email) throw new Error('no-email');

  return { email: String(payload.email).toLowerCase() };
}

// Адміністратори зберігаються як { email, role } — role: 'owner' (керує списком
// адмінів) або 'sender' (може надсилати розсилки й опитування, бачити статистику,
// але не додавати/прибирати інших адмінів чи міняти ролі).
async function getAdminRecords(env) {
  let list = await env.PUSH_KV.get(ADMIN_KEY, 'json');
  if (!Array.isArray(list) || !list.length) {
    list = [{ email: DEFAULT_ADMIN_EMAIL, role: 'owner' }];
    await env.PUSH_KV.put(ADMIN_KEY, JSON.stringify(list));
    return list;
  }
  // Міграція зі старого формату (масив рядків-пошт) — усім присвоюємо "owner",
  // щоб ніхто не втратив доступ після оновлення коду.
  if (typeof list[0] === 'string') {
    list = list.map(e => ({ email: String(e).toLowerCase(), role: 'owner' }));
    await env.PUSH_KV.put(ADMIN_KEY, JSON.stringify(list));
  }
  return list.map(a => ({ email: String(a.email).toLowerCase(), role: a.role === 'sender' ? 'sender' : 'owner' }));
}
async function setAdminRecords(env, list) {
  const clean = [];
  const seen = new Set();
  for (const a of list) {
    const email = String(a.email || '').trim().toLowerCase();
    if (!email || !email.includes('@') || seen.has(email)) continue;
    seen.add(email);
    clean.push({ email, role: a.role === 'sender' ? 'sender' : 'owner' });
  }
  await env.PUSH_KV.put(ADMIN_KEY, JSON.stringify(clean));
  return clean;
}
async function getAdminEmails(env) { return (await getAdminRecords(env)).map(a => a.email); }

// ===== Заготовки повідомлень =====
async function getTemplates(env) {
  const list = await env.PUSH_KV.get(TEMPLATES_KEY, 'json');
  return Array.isArray(list) ? list : [];
}
async function setTemplates(env, list) {
  const clean = list.slice(0, 50);
  await env.PUSH_KV.put(TEMPLATES_KEY, JSON.stringify(clean));
  return clean;
}

// ===== Історія розсилок (останні 30) =====
async function getHistory(env) {
  const list = await env.PUSH_KV.get(HISTORY_KEY, 'json');
  return Array.isArray(list) ? list : [];
}
async function addHistoryEntry(env, entry) {
  const list = await getHistory(env);
  list.unshift(entry);
  await env.PUSH_KV.put(HISTORY_KEY, JSON.stringify(list.slice(0, 30)));
}

// ===== Заплановані розсилки =====
async function getScheduled(env) {
  const list = await env.PUSH_KV.get(SCHEDULED_KEY, 'json');
  return Array.isArray(list) ? list : [];
}
async function setScheduled(env, list) {
  await env.PUSH_KV.put(SCHEDULED_KEY, JSON.stringify(list.slice(0, 100)));
  return list;
}

// ===== Графік росту (кількість пристроїв по днях, останні 90) =====
async function getGrowth(env) {
  const list = await env.PUSH_KV.get(GROWTH_KEY, 'json');
  return Array.isArray(list) ? list : [];
}
async function recordGrowthSnapshot(env, deviceCount) {
  const log = await getGrowth(env);
  const today = new Date().toISOString().slice(0, 10);
  const last = log[log.length - 1];
  if (last && last.date === today) {
    if (last.count === deviceCount) return; // нічого не змінилось — зайвий запис у KV не пишемо
    last.count = deviceCount;
  } else {
    log.push({ date: today, count: deviceCount });
  }
  await env.PUSH_KV.put(GROWTH_KEY, JSON.stringify(log.slice(-90)));
}

// ===== Лог видалених "мертвих" підписок (404/410 від Web Push) =====
async function getDeadLog(env) {
  const list = await env.PUSH_KV.get(DEAD_LOG_KEY, 'json');
  return Array.isArray(list) ? list : [];
}
async function logDeadSubscription(env, id) {
  const list = await getDeadLog(env);
  list.unshift({ id, at: Date.now() });
  await env.PUSH_KV.put(DEAD_LOG_KEY, JSON.stringify(list.slice(0, 200)));
}

// ===== Зворотний зв'язок від користувачів (форма в Профілі) =====
async function getFeedback(env) {
  const list = await env.PUSH_KV.get(FEEDBACK_KEY, 'json');
  return Array.isArray(list) ? list : [];
}
async function addFeedback(env, entry) {
  const list = await getFeedback(env);
  list.unshift(entry);
  await env.PUSH_KV.put(FEEDBACK_KEY, JSON.stringify(list.slice(0, 200)));
}
// Необов'язково: якщо в Cloudflare додано TELEGRAM_BOT_TOKEN і TELEGRAM_CHAT_ID
// (Settings → Variables), кожен відгук ще й дублюється в Telegram. Без цих
// змінних відгуки просто зберігаються в KV і видно їх в адмінці.
async function notifyTelegram(env, text) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text: text.slice(0, 4000) }),
    });
  } catch (e) { /* Telegram недоступний — не критично, відгук уже в KV */ }
}

// ===== Лог дій адміністраторів (хто що зробив, для прозорості) =====
async function getActionLog(env) {
  const list = await env.PUSH_KV.get(ACTION_LOG_KEY, 'json');
  return Array.isArray(list) ? list : [];
}
async function logAction(env, email, action, details) {
  const list = await getActionLog(env);
  list.unshift({ email, action, details: details || '', at: Date.now() });
  await env.PUSH_KV.put(ACTION_LOG_KEY, JSON.stringify(list.slice(0, 100)));
}

// ===== Опитування (push із питанням + варіантами відповіді) =====
async function getPolls(env) {
  const list = await env.PUSH_KV.get(POLLS_KEY, 'json');
  return Array.isArray(list) ? list : [];
}
async function setPolls(env, list) {
  await env.PUSH_KV.put(POLLS_KEY, JSON.stringify(list.slice(0, 50)));
  return list;
}
function pollVotesKey(id) { return POLL_VOTES_PREFIX + id; }
async function getPollVotes(env, id) {
  const data = await env.PUSH_KV.get(pollVotesKey(id), 'json');
  return data && typeof data === 'object' ? data : { counts: {}, voters: [] };
}

// ===== "Жива" активна зміна (без жодних фінансових даних — лише час старту й
// назва авто) — щоб раз на ~15 хв оновлювати одне push-сповіщення з тривалістю,
// поки водій за кермом. Ідея-заміна справжнього Live Activity, якого сайт
// технічно створити не може (це нативна технологія Apple/Google).
async function getLiveShifts(env) {
  const data = await env.PUSH_KV.get(LIVE_SHIFTS_KEY, 'json');
  return data && typeof data === 'object' ? data : {};
}
async function setLiveShifts(env, obj) {
  await env.PUSH_KV.put(LIVE_SHIFTS_KEY, JSON.stringify(obj));
}
function fmtDurUA(ms) {
  const totalMin = Math.max(0, Math.round(ms / 60000));
  const h = Math.floor(totalMin / 60), m = totalMin % 60;
  if (h <= 0) return `${m} хв`;
  return `${h} год${m ? ' ' + m + ' хв' : ''}`;
}

// ===== Анонімний бенчмарк (₴/год по платформах) — суворо опційно з боку
// клієнта, без дат, без прив'язки до конкретного водія в даних, які тут
// зберігаються: лише число ₴/год і випадковий deviceId, ніяких сум доходу,
// витрат чи інших фінансових деталей.
function benchmarkKey(platformId) { return BENCHMARK_PREFIX + platformId; }
async function getBenchmarkSamples(env, platformId) {
  const list = await env.PUSH_KV.get(benchmarkKey(platformId), 'json');
  return Array.isArray(list) ? list : [];
}
async function addBenchmarkSample(env, platformId, rate) {
  const list = await getBenchmarkSamples(env, platformId);
  list.push(rate);
  await env.PUSH_KV.put(benchmarkKey(platformId), JSON.stringify(list.slice(-500)));
}
function median(arr) {
  const s = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

// ===== Детальна статистика для адмінки — суворо опційно з боку клієнта (за
// замовчуванням вимкнено), окремо від коротких дедлайн-підписів у /register.
// Ключується за deviceId (тим самим анонімним ідентифікатором, що й push-підписка),
// і містить ім'я лише якщо водій сам це окремо дозволив.
async function getDetailedStats(env) {
  const data = await env.PUSH_KV.get(DETAILED_STATS_KEY, 'json');
  return data && typeof data === 'object' ? data : {};
}
async function setDetailedStats(env, obj) {
  await env.PUSH_KV.put(DETAILED_STATS_KEY, JSON.stringify(obj));
}

// Спільна логіка розсилки всім/сегменту — використовується і миттєвою відправкою,
// і запланованими розсилками, коли настає їхній час.
async function broadcastPush(env, { title, body, segment, url, hid }) {
  const weekAgo = Date.now() - 7 * 86400000;
  const list = await env.PUSH_KV.list();
  let sent = 0, failed = 0, skipped = 0;
  for (const key of list.keys) {
    if (isReservedKey(key.name)) continue;
    const record = await env.PUSH_KV.get(key.name, 'json');
    if (!record || !record.subscription) continue;
    if (segment === 'inactive7d' && record.updatedAt && record.updatedAt >= weekAgo) { skipped++; continue; }
    if (segment === 'new7d' && !(record.createdAt && record.createdAt >= weekAgo)) { skipped++; continue; }
    try {
      const resp = await sendWebPush(env, record.subscription, { title, body, tag: 'vodiy-admin', url: deepLinkToHash(url), hid: hid || undefined });
      if (resp.ok) sent++;
      else {
        failed++;
        if (resp.status === 404 || resp.status === 410) { await env.PUSH_KV.delete(key.name); await logDeadSubscription(env, key.name); }
      }
    } catch (e) { failed++; }
  }
  return { sent, failed, skipped };
}

// Перевіряє ID-токен із тіла запиту й переконується, що ця пошта — у списку
// адміністраторів. Кидає помилку з .status, яку обробники нижче віддають як є.
async function requireAdmin(request, env, opts) {
  const body = await request.json().catch(() => ({}));
  let email;
  try {
    ({ email } = await verifyGoogleIdToken(body.idToken));
  } catch (e) {
    const err = new Error('bad-token'); err.status = 401; throw err;
  }
  const records = await getAdminRecords(env);
  const me = records.find(a => a.email === email);
  if (!me) {
    const err = new Error('not-admin'); err.status = 403; throw err;
  }
  if (opts && opts.ownerOnly && me.role !== 'owner') {
    const err = new Error('owner-only'); err.status = 403; throw err;
  }
  return { email, role: me.role, body, admins: records.map(a => a.email), adminRecords: records };
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });
    const url = new URL(request.url);

    if (url.pathname === '/register' && request.method === 'POST') {
      if (!checkSecret(request, env)) return json({ error: 'forbidden' }, 403);
      const body = await request.json();
      if (!body.id || !body.subscription) return json({ error: 'bad request' }, 400);
      const existing = await env.PUSH_KV.get(body.id, 'json');
      const record = {
        subscription: body.subscription,
        items: Array.isArray(body.items) ? body.items.slice(0, 50) : [],
        notified: (existing && existing.notified) || [],
        createdAt: (existing && existing.createdAt) || Date.now(),
        updatedAt: Date.now(),
        platform: classifyPlatform(request.headers.get('User-Agent')),
      };
      // прибираємо зі списку "вже сповіщено" ті id, яких більше немає в items (щоб повторно нагадало наступного разу)
      const activeIds = new Set(record.items.map(it => it.id));
      record.notified = record.notified.filter(nid => activeIds.has(nid));
      await env.PUSH_KV.put(body.id, JSON.stringify(record));
      return json({ ok: true });
    }

    if (url.pathname === '/unregister' && request.method === 'POST') {
      if (!checkSecret(request, env)) return json({ error: 'forbidden' }, 403);
      const body = await request.json();
      if (body.id) await env.PUSH_KV.delete(body.id);
      return json({ ok: true });
    }

    if (url.pathname === '/test' && request.method === 'POST') {
      if (!checkSecret(request, env)) return json({ error: 'forbidden' }, 403);
      const body = await request.json();
      if (!body.id) return json({ error: 'bad request' }, 400);
      const record = await env.PUSH_KV.get(body.id, 'json');
      if (!record) return json({ error: 'not found' }, 404);
      try {
        const resp = await sendWebPush(env, record.subscription, {
          title: 'Водій', body: 'Тестове сповіщення — усе працює 🎉', tag: 'vodiy-test',
        });
        return json({ ok: resp.ok, status: resp.status });
      } catch (e) {
        return json({ ok: false, error: String(e) }, 500);
      }
    }

    // Дозволяє застосунку (не адмінці) тихо перевірити після синхронізації з Google
    // Диском, чи входить щойно підтверджена пошта в білий список адміністраторів —
    // щоб показати чи приховати кнопку "Адмінка" в Профілі. Приймає звичайний OAuth
    // access-токен (той самий, що й для Google Диска), а не ID-токен адмінки: пошту
    // перевіряємо тут-таки на сервері через userinfo, клієнту не довіряємо на слово.
    if (url.pathname === '/admin/check-access' && request.method === 'POST') {
      if (!checkSecret(request, env)) return json({ error: 'forbidden' }, 403);
      try {
        const body = await request.json();
        if (!body.accessToken) return json({ ok: false, error: 'no-token' }, 400);
        const resp = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
          headers: { Authorization: 'Bearer ' + body.accessToken },
        });
        if (!resp.ok) return json({ ok: false, error: 'bad-token' }, 401);
        const info = await resp.json();
        if (!info.email || (info.email_verified !== true && info.email_verified !== 'true')) {
          return json({ ok: false, error: 'email-not-verified' }, 401);
        }
        const email = String(info.email).toLowerCase();
        const admins = await getAdminEmails(env);
        return json({ ok: true, email, isAdmin: admins.includes(email) });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, 500);
      }
    }

    // ===== Адмінка =====
    if (url.pathname === '/admin/whoami' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { email } = await verifyGoogleIdToken(body.idToken);
        const records = await getAdminRecords(env);
        const me = records.find(a => a.email === email);
        return json({ ok: true, email, isAdmin: !!me, role: me ? me.role : null });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, 401);
      }
    }

    if (url.pathname === '/admin/list' && request.method === 'POST') {
      try {
        const { email, adminRecords } = await requireAdmin(request, env);
        return json({ ok: true, admins: adminRecords, me: email });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    if (url.pathname === '/admin/add' && request.method === 'POST') {
      try {
        const { body, email, adminRecords } = await requireAdmin(request, env, { ownerOnly: true });
        const newEmail = String(body.email || '').trim().toLowerCase();
        if (!newEmail || !newEmail.includes('@')) return json({ ok: false, error: 'bad-email' }, 400);
        const role = body.role === 'sender' ? 'sender' : 'owner';
        const updated = await setAdminRecords(env, [...adminRecords.filter(a => a.email !== newEmail), { email: newEmail, role }]);
        await logAction(env, email, 'admin_add', `${newEmail} (${role})`);
        return json({ ok: true, admins: updated });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    if (url.pathname === '/admin/remove' && request.method === 'POST') {
      try {
        const { body, email, adminRecords } = await requireAdmin(request, env, { ownerOnly: true });
        const target = String(body.email || '').trim().toLowerCase();
        const owners = adminRecords.filter(a => a.role === 'owner');
        const targetRec = adminRecords.find(a => a.email === target);
        if (!targetRec) return json({ ok: false, error: 'not-found' }, 404);
        if (targetRec.role === 'owner' && owners.length <= 1) return json({ ok: false, error: 'last-owner' }, 400);
        const updated = await setAdminRecords(env, adminRecords.filter(a => a.email !== target));
        await logAction(env, email, 'admin_remove', target);
        return json({ ok: true, admins: updated });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    if (url.pathname === '/admin/set-role' && request.method === 'POST') {
      try {
        const { body, email, adminRecords } = await requireAdmin(request, env, { ownerOnly: true });
        const target = String(body.email || '').trim().toLowerCase();
        const role = body.role === 'sender' ? 'sender' : 'owner';
        const targetRec = adminRecords.find(a => a.email === target);
        if (!targetRec) return json({ ok: false, error: 'not-found' }, 404);
        const owners = adminRecords.filter(a => a.role === 'owner');
        if (targetRec.role === 'owner' && role === 'sender' && owners.length <= 1) return json({ ok: false, error: 'last-owner' }, 400);
        targetRec.role = role;
        const updated = await setAdminRecords(env, adminRecords);
        await logAction(env, email, 'admin_role', `${target} → ${role}`);
        return json({ ok: true, admins: updated });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    if (url.pathname === '/admin/stats' && request.method === 'POST') {
      try {
        await requireAdmin(request, env);
        const list = await env.PUSH_KV.list();
        const records = list.keys.filter(k => !isReservedKey(k.name));
        const count = records.length;
        // скільки пристроїв синхронізувались за останні 7 днів — грубий орієнтир активності
        const weekAgo = Date.now() - 7 * 86400000;
        let active7d = 0;
        const platforms = {};
        for (const key of records) {
          const rec = await env.PUSH_KV.get(key.name, 'json');
          if (!rec) continue;
          if (rec.updatedAt && rec.updatedAt >= weekAgo) active7d++;
          const p = rec.platform || 'Інше';
          platforms[p] = (platforms[p] || 0) + 1;
        }
        return json({ ok: true, devices: count, active7d, platforms });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    if (url.pathname === '/admin/send' && request.method === 'POST') {
      try {
        const { body, email } = await requireAdmin(request, env);
        const title = String(body.title || 'Водій').trim().slice(0, 120) || 'Водій';
        const text = String(body.body || '').trim().slice(0, 500);
        if (!text) return json({ ok: false, error: 'empty-body' }, 400);
        const segment = ['inactive7d', 'new7d'].includes(body.segment) ? body.segment : 'all';
        const link = DEEP_LINK_TARGETS.has(body.url) ? body.url : '';
        const hid = crypto.randomUUID();
        const { sent, failed, skipped } = await broadcastPush(env, { title, body: text, segment, url: link, hid });
        await addHistoryEntry(env, { id: hid, title, body: text, sentAt: Date.now(), sent, failed, clicks: 0, segment, url: link, byEmail: email });
        await logAction(env, email, 'send', `«${title}» → ${segment} (${sent} надіслано)`);
        return json({ ok: true, sent, failed, skipped, hid });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    // ===== Клік по сповіщенню (від service worker, для підрахунку CTR) =====
    if (url.pathname === '/track/click' && request.method === 'POST') {
      if (!checkSecret(request, env)) return json({ error: 'forbidden' }, 403);
      try {
        const body = await request.json();
        if (body.hid) {
          const list = await getHistory(env);
          const entry = list.find(h => h.id === body.hid);
          if (entry) { entry.clicks = (entry.clicks || 0) + 1; await env.PUSH_KV.put(HISTORY_KEY, JSON.stringify(list)); }
        }
      } catch (e) { /* трекінг кліків не критичний — тихо ігноруємо помилки */ }
      return json({ ok: true });
    }

    // ===== Заплановані розсилки =====
    if (url.pathname === '/admin/schedule/list' && request.method === 'POST') {
      try {
        await requireAdmin(request, env);
        const scheduled = (await getScheduled(env)).sort((a, b) => a.sendAt - b.sendAt);
        return json({ ok: true, scheduled });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    if (url.pathname === '/admin/schedule/create' && request.method === 'POST') {
      try {
        const { body, email } = await requireAdmin(request, env);
        const title = String(body.title || 'Водій').trim().slice(0, 120) || 'Водій';
        const text = String(body.body || '').trim().slice(0, 500);
        const sendAt = Number(body.sendAt);
        if (!text) return json({ ok: false, error: 'empty-body' }, 400);
        if (!sendAt || !Number.isFinite(sendAt) || sendAt <= Date.now()) return json({ ok: false, error: 'bad-time' }, 400);
        const segment = ['inactive7d', 'new7d'].includes(body.segment) ? body.segment : 'all';
        const link = DEEP_LINK_TARGETS.has(body.url) ? body.url : '';
        const scheduled = await getScheduled(env);
        scheduled.push({ id: crypto.randomUUID(), title, body: text, segment, url: link, sendAt, createdBy: email, createdAt: Date.now() });
        await setScheduled(env, scheduled);
        await logAction(env, email, 'schedule_create', `«${title}» на ${new Date(sendAt).toLocaleString('uk-UA')}`);
        return json({ ok: true, scheduled: scheduled.sort((a, b) => a.sendAt - b.sendAt) });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    if (url.pathname === '/admin/schedule/update' && request.method === 'POST') {
      try {
        const { body, email } = await requireAdmin(request, env);
        const scheduled = await getScheduled(env);
        const item = scheduled.find(s => s.id === body.id);
        if (!item) return json({ ok: false, error: 'not-found' }, 404);
        if (body.title !== undefined) item.title = String(body.title).trim().slice(0, 120) || 'Водій';
        if (body.body !== undefined) {
          const t = String(body.body).trim().slice(0, 500);
          if (!t) return json({ ok: false, error: 'empty-body' }, 400);
          item.body = t;
        }
        if (body.segment !== undefined) item.segment = ['inactive7d', 'new7d'].includes(body.segment) ? body.segment : 'all';
        if (body.url !== undefined) item.url = DEEP_LINK_TARGETS.has(body.url) ? body.url : '';
        if (body.sendAt !== undefined) {
          const sendAt = Number(body.sendAt);
          if (!sendAt || !Number.isFinite(sendAt) || sendAt <= Date.now()) return json({ ok: false, error: 'bad-time' }, 400);
          item.sendAt = sendAt;
        }
        await setScheduled(env, scheduled);
        await logAction(env, email, 'schedule_update', `«${item.title}»`);
        return json({ ok: true, scheduled: scheduled.sort((a, b) => a.sendAt - b.sendAt) });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    if (url.pathname === '/admin/schedule/cancel' && request.method === 'POST') {
      try {
        const { body, email } = await requireAdmin(request, env);
        const scheduled = (await getScheduled(env)).filter(s => s.id !== body.id);
        await setScheduled(env, scheduled);
        await logAction(env, email, 'schedule_cancel', body.id || '');
        return json({ ok: true, scheduled: scheduled.sort((a, b) => a.sendAt - b.sendAt) });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    // ===== Графік росту =====
    if (url.pathname === '/admin/growth' && request.method === 'POST') {
      try {
        await requireAdmin(request, env);
        return json({ ok: true, growth: await getGrowth(env) });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    // ===== Заготовки повідомлень =====
    if (url.pathname === '/admin/templates/list' && request.method === 'POST') {
      try {
        await requireAdmin(request, env);
        return json({ ok: true, templates: await getTemplates(env) });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    if (url.pathname === '/admin/templates/save' && request.method === 'POST') {
      try {
        const { body, email } = await requireAdmin(request, env);
        const title = String(body.title || '').trim().slice(0, 120);
        const text = String(body.body || '').trim().slice(0, 500);
        const emoji = String(body.emoji || '').trim().slice(0, 4);
        const category = String(body.category || '').trim().slice(0, 30);
        if (!title && !text) return json({ ok: false, error: 'empty' }, 400);
        const templates = await getTemplates(env);
        if (body.id) {
          const t = templates.find(x => x.id === body.id);
          if (t) { t.title = title; t.body = text; t.emoji = emoji; t.category = category; }
          else templates.unshift({ id: body.id, title, body: text, emoji, category });
        } else {
          templates.unshift({ id: crypto.randomUUID(), title, body: text, emoji, category });
        }
        await logAction(env, email, 'template_save', title || '(без заголовка)');
        return json({ ok: true, templates: await setTemplates(env, templates) });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    if (url.pathname === '/admin/templates/delete' && request.method === 'POST') {
      try {
        const { body, email } = await requireAdmin(request, env);
        const templates = (await getTemplates(env)).filter(t => t.id !== body.id);
        await logAction(env, email, 'template_delete', body.id || '');
        return json({ ok: true, templates: await setTemplates(env, templates) });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    // ===== Історія розсилок =====
    if (url.pathname === '/admin/history' && request.method === 'POST') {
      try {
        await requireAdmin(request, env);
        return json({ ok: true, history: await getHistory(env) });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    // ===== Лог видалених "мертвих" підписок =====
    if (url.pathname === '/admin/dead-log' && request.method === 'POST') {
      try {
        await requireAdmin(request, env);
        const log = await getDeadLog(env);
        const weekAgo = Date.now() - 7 * 86400000;
        return json({ ok: true, log: log.slice(0, 50), last7d: log.filter(l => l.at >= weekAgo).length, total: log.length });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    // ===== Лог дій адміністраторів =====
    if (url.pathname === '/admin/action-log' && request.method === 'POST') {
      try {
        await requireAdmin(request, env);
        return json({ ok: true, log: await getActionLog(env) });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    // ===== Зворотний зв'язок від користувача (форма в Профілі застосунку) =====
    if (url.pathname === '/feedback' && request.method === 'POST') {
      if (!checkSecret(request, env)) return json({ error: 'forbidden' }, 403);
      try {
        const body = await request.json();
        const text = String(body.text || '').trim().slice(0, 1000);
        if (!text) return json({ ok: false, error: 'empty' }, 400);
        const contact = String(body.contact || '').trim().slice(0, 200);
        const entry = { text, contact, at: Date.now() };
        await addFeedback(env, entry);
        await notifyTelegram(env, `📩 Відгук у «Водій»${contact ? ` від ${contact}` : ''}:\n${text}`);
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, 500);
      }
    }

    if (url.pathname === '/admin/feedback' && request.method === 'POST') {
      try {
        await requireAdmin(request, env);
        return json({ ok: true, feedback: await getFeedback(env) });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    // ===== Опитування =====
    if (url.pathname === '/admin/poll/create' && request.method === 'POST') {
      try {
        const { body, email } = await requireAdmin(request, env);
        const question = String(body.question || '').trim().slice(0, 200);
        const options = Array.isArray(body.options)
          ? body.options.map(o => String(o).trim().slice(0, 60)).filter(Boolean).slice(0, 5)
          : [];
        if (!question || options.length < 2) return json({ ok: false, error: 'bad-poll' }, 400);
        const segment = ['inactive7d', 'new7d'].includes(body.segment) ? body.segment : 'all';
        const id = crypto.randomUUID();
        const polls = await getPolls(env);
        const poll = { id, question, options, segment, createdBy: email, createdAt: Date.now() };
        polls.unshift(poll);
        await setPolls(env, polls);
        const hid = crypto.randomUUID();
        const { sent, failed } = await broadcastPush(env, { title: '🗳 Опитування', body: question, segment, url: 'poll-' + id, hid });
        await addHistoryEntry(env, { id: hid, title: '🗳 Опитування', body: question, sentAt: Date.now(), sent, failed, clicks: 0, segment, url: 'poll-' + id, byEmail: email, poll: true, pollId: id });
        await logAction(env, email, 'poll_create', question);
        return json({ ok: true, poll, sent, failed });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    if (url.pathname === '/admin/poll/list' && request.method === 'POST') {
      try {
        await requireAdmin(request, env);
        return json({ ok: true, polls: await getPolls(env) });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    if (url.pathname === '/admin/poll/results' && request.method === 'POST') {
      try {
        const { body } = await requireAdmin(request, env);
        const votes = await getPollVotes(env, body.id);
        return json({ ok: true, counts: votes.counts || {}, total: (votes.voters || []).length });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    // Публічно (з застосунку, не адмінки) — прочитати текст опитування за посиланням із push.
    if (url.pathname === '/poll/get' && request.method === 'POST') {
      if (!checkSecret(request, env)) return json({ error: 'forbidden' }, 403);
      try {
        const body = await request.json();
        const polls = await getPolls(env);
        const poll = polls.find(p => p.id === body.id);
        if (!poll) return json({ ok: false, error: 'not-found' }, 404);
        return json({ ok: true, question: poll.question, options: poll.options });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, 500);
      }
    }

    // Публічно — проголосувати. Дедуплікація за deviceId (той самий id, що й для push).
    if (url.pathname === '/poll/vote' && request.method === 'POST') {
      if (!checkSecret(request, env)) return json({ error: 'forbidden' }, 403);
      try {
        const body = await request.json();
        const pollId = String(body.pollId || '');
        const deviceId = String(body.deviceId || '');
        const optionIndex = Number(body.optionIndex);
        if (!deviceId) return json({ ok: false, error: 'no-device' }, 400);
        const polls = await getPolls(env);
        const poll = polls.find(p => p.id === pollId);
        if (!poll) return json({ ok: false, error: 'not-found' }, 404);
        if (!Number.isInteger(optionIndex) || optionIndex < 0 || optionIndex >= poll.options.length) {
          return json({ ok: false, error: 'bad-option' }, 400);
        }
        const votes = await getPollVotes(env, pollId);
        votes.counts = votes.counts || {};
        votes.voters = votes.voters || [];
        if (votes.voters.includes(deviceId)) return json({ ok: true, already: true });
        votes.voters.push(deviceId);
        votes.counts[optionIndex] = (votes.counts[optionIndex] || 0) + 1;
        await env.PUSH_KV.put(pollVotesKey(pollId), JSON.stringify(votes));
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, 500);
      }
    }

    // ===== "Жива" зміна (публічно, з застосунку) — жодних фінансових даних,
    // лише час старту й, за бажанням, назва авто.
    if (url.pathname === '/shift/live-start' && request.method === 'POST') {
      if (!checkSecret(request, env)) return json({ error: 'forbidden' }, 403);
      try {
        const body = await request.json();
        if (!body.id || !body.startTime) return json({ ok: false, error: 'bad-request' }, 400);
        const liveShifts = await getLiveShifts(env);
        liveShifts[body.id] = {
          startTime: Number(body.startTime),
          carName: String(body.carName || '').trim().slice(0, 60),
          lastNotifiedMin: 0,
        };
        await setLiveShifts(env, liveShifts);
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, 500);
      }
    }

    if (url.pathname === '/shift/live-stop' && request.method === 'POST') {
      if (!checkSecret(request, env)) return json({ error: 'forbidden' }, 403);
      try {
        const body = await request.json();
        const liveShifts = await getLiveShifts(env);
        if (body.id && liveShifts[body.id]) {
          delete liveShifts[body.id];
          await setLiveShifts(env, liveShifts);
        }
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, 500);
      }
    }

    // ===== Анонімний бенчмарк заробітку (опційно, вимикається в Налаштуваннях) =====
    if (url.pathname === '/benchmark/submit' && request.method === 'POST') {
      if (!checkSecret(request, env)) return json({ error: 'forbidden' }, 403);
      try {
        const body = await request.json();
        const platformId = String(body.platformId || '').trim().slice(0, 40);
        const rate = Number(body.uahPerHour);
        if (!platformId || !Number.isFinite(rate) || rate <= 0 || rate > 5000) {
          return json({ ok: false, error: 'bad-request' }, 400);
        }
        await addBenchmarkSample(env, platformId, Math.round(rate));
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, 500);
      }
    }

    if (url.pathname === '/benchmark/get' && request.method === 'POST') {
      if (!checkSecret(request, env)) return json({ error: 'forbidden' }, 403);
      try {
        const body = await request.json();
        const platformId = String(body.platformId || '').trim().slice(0, 40);
        if (!platformId) return json({ ok: false, error: 'bad-request' }, 400);
        const samples = await getBenchmarkSamples(env, platformId);
        const MIN_SAMPLES = 5; // не показуємо агрегат, поки замало даних — щоб не палити чужі поодинокі значення
        if (samples.length < MIN_SAMPLES) return json({ ok: true, enough: false, count: samples.length });
        const avg = samples.reduce((a, b) => a + b, 0) / samples.length;
        return json({ ok: true, enough: true, count: samples.length, avg: Math.round(avg), median: Math.round(median(samples)) });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, 500);
      }
    }

    // ===== Детальна статистика (опційно, за замовчуванням вимкнено) =====
    if (url.pathname === '/stats/submit' && request.method === 'POST') {
      if (!checkSecret(request, env)) return json({ error: 'forbidden' }, 403);
      try {
        const body = await request.json();
        if (!body.id) return json({ ok: false, error: 'bad-request' }, 400);
        const totalIncome = Number(body.totalIncome);
        const totalHours = Number(body.totalHours);
        const totalShifts = Number(body.totalShifts);
        const carsCount = Number(body.carsCount);
        if (!Number.isFinite(totalIncome) || totalIncome < 0 || totalIncome > 100000000) return json({ ok: false, error: 'bad-request' }, 400);
        const platforms = Array.isArray(body.platforms) ? body.platforms.slice(0, 20).map(p => ({
          name: String(p.name || 'Інше').trim().slice(0, 40) || 'Інше',
          income: Math.max(0, Math.round(Number(p.income) || 0)),
          shifts: Math.max(0, Math.round(Number(p.shifts) || 0)),
        })).filter(p => p.income > 0 || p.shifts > 0) : [];
        const stats = await getDetailedStats(env);
        stats[body.id] = {
          name: String(body.name || '').trim().slice(0, 40),
          totalIncome: Math.round(totalIncome),
          totalHours: Number.isFinite(totalHours) ? Math.max(0, Math.round(totalHours * 10) / 10) : 0,
          totalShifts: Number.isFinite(totalShifts) ? Math.max(0, Math.round(totalShifts)) : 0,
          carsCount: Number.isFinite(carsCount) ? Math.max(0, Math.round(carsCount)) : 0,
          platforms,
          updatedAt: Date.now(),
        };
        await setDetailedStats(env, stats);
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, 500);
      }
    }

    if (url.pathname === '/stats/clear' && request.method === 'POST') {
      if (!checkSecret(request, env)) return json({ error: 'forbidden' }, 403);
      try {
        const body = await request.json();
        if (body.id) {
          const stats = await getDetailedStats(env);
          if (stats[body.id]) { delete stats[body.id]; await setDetailedStats(env, stats); }
        }
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, 500);
      }
    }

    if (url.pathname === '/admin/detailed-stats' && request.method === 'POST') {
      try {
        await requireAdmin(request, env);
        const stats = await getDetailedStats(env);
        const entries = Object.entries(stats);
        const n = entries.length;
        const totalIncomes = entries.map(([, v]) => v.totalIncome || 0);
        const byPlatform = {}; // name -> { drivers:Set-ish count, income, shifts, incomes:[] }
        const named = [];
        entries.forEach(([id, v]) => {
          (v.platforms || []).forEach(p => {
            const key = p.name || 'Інше';
            byPlatform[key] = byPlatform[key] || { drivers: 0, income: 0, shifts: 0, incomes: [] };
            byPlatform[key].drivers++;
            byPlatform[key].income += p.income || 0;
            byPlatform[key].shifts += p.shifts || 0;
            byPlatform[key].incomes.push(p.income || 0);
          });
          if (v.name) named.push({ name: v.name, totalIncome: v.totalIncome || 0, totalHours: v.totalHours || 0, totalShifts: v.totalShifts || 0, carsCount: v.carsCount || 0, updatedAt: v.updatedAt });
        });
        const platforms = Object.entries(byPlatform).map(([name, v]) => ({
          name, drivers: v.drivers, totalIncome: Math.round(v.income), totalShifts: v.shifts,
          avgIncome: Math.round(v.income / v.drivers),
          maxIncome: Math.round(Math.max(...v.incomes)),
          minIncome: Math.round(Math.min(...v.incomes)),
        })).sort((a, b) => b.drivers - a.drivers);
        const overall = n ? {
          drivers: n,
          avgIncome: Math.round(totalIncomes.reduce((a, b) => a + b, 0) / n),
          maxIncome: Math.round(Math.max(...totalIncomes)),
          minIncome: Math.round(Math.min(...totalIncomes)),
          totalHours: Math.round(entries.reduce((a, [, v]) => a + (v.totalHours || 0), 0)),
          totalShifts: entries.reduce((a, [, v]) => a + (v.totalShifts || 0), 0),
        } : null;
        named.sort((a, b) => b.totalIncome - a.totalIncome);
        return json({ ok: true, overall, platforms, named });
      } catch (e) {
        return json({ ok: false, error: String(e.message || e) }, e.status || 403);
      }
    }

    return json({ ok: true, service: 'vodiy-push-worker' });
  },

  async scheduled(event, env, ctx) {
    const list = await env.PUSH_KV.list();
    const deviceKeys = list.keys.filter(k => !isReservedKey(k.name));

    // 1) щоденні нагадування про дедлайни (податки, страховка, ТО тощо)
    for (const key of deviceKeys) {
      const record = await env.PUSH_KV.get(key.name, 'json');
      if (!record || !record.subscription) continue;
      await checkAndNotify(env, key.name, record);
    }

    // 2) заплановані адмінкою розсилки, час яких настав
    const scheduled = await getScheduled(env);
    const due = scheduled.filter(s => s.sendAt <= Date.now());
    if (due.length) {
      for (const s of due) {
        const hid = crypto.randomUUID();
        const { sent, failed } = await broadcastPush(env, { title: s.title, body: s.body, segment: s.segment, url: s.url, hid });
        await addHistoryEntry(env, { id: hid, title: s.title, body: s.body, sentAt: Date.now(), sent, failed, clicks: 0, segment: s.segment, url: s.url, byEmail: s.createdBy, scheduled: true });
      }
      await setScheduled(env, scheduled.filter(s => s.sendAt > Date.now()));
    }

    // 3) "жива" зміна — оновлюємо (замінюємо за tag) сповіщення з тривалістю для
    // кожної активної зміни, по якій застосунок повідомив старт. Без сум і доходу.
    const liveShifts = await getLiveShifts(env);
    const liveIds = Object.keys(liveShifts);
    if (liveIds.length) {
      let changed = false;
      for (const id of liveIds) {
        const ls = liveShifts[id];
        const elapsedMs = Date.now() - ls.startTime;
        // застаріла (>20 год) — водій забув завершити зміну в застосунку чи щось пішло не так,
        // прибираємо, щоб не слати вічні сповіщення.
        if (elapsedMs > 20 * 3600000) { delete liveShifts[id]; changed = true; continue; }
        const record = await env.PUSH_KV.get(id, 'json');
        if (!record || !record.subscription) { delete liveShifts[id]; changed = true; continue; }
        const title = ls.carName ? `Зміна · ${ls.carName}` : 'Активна зміна';
        const body = `Триває вже ${fmtDurUA(elapsedMs)}. Не забудь завершити, коли закінчиш.`;
        try {
          const resp = await sendWebPush(env, record.subscription, { title, body, tag: 'vodiy-live-shift', url: './#dash' });
          if (resp.status === 404 || resp.status === 410) {
            await env.PUSH_KV.delete(id);
            await logDeadSubscription(env, id);
            delete liveShifts[id]; changed = true;
          }
        } catch (e) { /* мережа підвела — спробуємо наступного разу */ }
      }
      if (changed) await setLiveShifts(env, liveShifts);
    }

    // 4) знімок кількості пристроїв для графіка росту (пишемо в KV, лише якщо змінилось)
    await recordGrowthSnapshot(env, deviceKeys.length);
  },
};
