const COOKIE = 'sanad_session';
const DAY = 60 * 60 * 24;
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
const fail = (message, status = 400) => json({ error: message }, status);
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64 = value => Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
async function hmacKey(secret) { return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign','verify']); }
async function sign(payload, secret) { const body = b64(enc.encode(JSON.stringify(payload))); const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(body)); return `${body}.${b64(sig)}`; }
async function verify(token, secret) { try { const [body, sig] = token.split('.'); if (!body || !sig) return null; const ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), unb64(sig), enc.encode(body)); if (!ok) return null; const p = JSON.parse(dec.decode(unb64(body))); return p.exp > Date.now()/1000 ? p : null; } catch { return null; } }
function cookieValue(request, name) { const all = request.headers.get('cookie') || ''; for (const part of all.split(';')) { const [k,...v] = part.trim().split('='); if (k === name) return v.join('='); } return ''; }
function setCookie(token, maxAge = 7*DAY) { return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`; }
async function hashPassword(password, pepper) { const salt = crypto.getRandomValues(new Uint8Array(16)); const material = `${password}\u0000${pepper}`; const key = await crypto.subtle.importKey('raw', enc.encode(material), 'PBKDF2', false, ['deriveBits']); const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', salt, iterations:20000, hash:'SHA-256' }, key, 256); return `pbkdf2$20000$${b64(salt)}$${b64(bits)}`; }
async function checkPassword(password, stored, pepper) { try { const [, rounds, salt, expected] = stored.split('$'); const material = `${password}\u0000${pepper}`; const key = await crypto.subtle.importKey('raw', enc.encode(material), 'PBKDF2', false, ['deriveBits']); const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', salt:unb64(salt), iterations:Number(rounds), hash:'SHA-256' }, key, 256); const a=unb64(expected), b=new Uint8Array(bits); return a.length===b.length && a.every((v,i)=>v===b[i]); } catch { return false; } }
const safeUser = u => ({ id:u.id, name:u.name, email:u.email, track:u.track, role:u.role || 'student', created_at:u.created_at });
async function body(request) { try { return await request.json(); } catch { return {}; } }
async function currentUser(request, env) { const token = cookieValue(request, COOKIE); if (!token) return null; const p = await verify(token, env.SESSION_SECRET); if (!p?.id) return null; return await env.DB.prepare('SELECT id,name,email,track,role,created_at FROM users WHERE id=?').bind(p.id).first(); }
function requireUser(user) { return user ? null : fail('سجّل الدخول أولًا.',401); }
function requireAdmin(user) { return !user ? fail('سجّل الدخول أولًا.',401) : user.role !== 'admin' ? fail('هذه الصفحة للمشرف فقط.',403) : null; }
const trackOK = t => ['thanaweya','bac2'].includes(t);

async function handleApi(request, env) {
 const url = new URL(request.url), path = url.pathname, method = request.method;
 const user = await currentUser(request, env);
 if (path === '/api/health' && method === 'GET') return json({ok:true, service:'sanad-worker'});
 if (path === '/api/auth/register' && method === 'POST') {
  const b=await body(request), name=String(b.name||'').trim(), email=String(b.email||'').trim().toLowerCase(), password=String(b.password||''), track=b.track;
  if(name.length<2||name.length>80) return fail('اكتب اسمًا صحيحًا.');
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail('البريد الإلكتروني غير صحيح.');
  if(password.length<8||password.length>128) return fail('كلمة المرور يجب ألا تقل عن 8 أحرف.');
  if(!trackOK(track)) return fail('اختر المسار الدراسي.');
  if(!env.PASSWORD_PEPPER) return fail('إعداد الخادم ناقص: أضف السر PASSWORD_PEPPER في إعدادات Cloudflare Workers ثم أعد النشر.',500);
  if(!env.SESSION_SECRET) return fail('إعداد الخادم ناقص: أضف السر SESSION_SECRET في إعدادات Cloudflare Workers ثم أعد النشر.',500);
  const hash=await hashPassword(password,env.PASSWORD_PEPPER);
  try { const r=await env.DB.prepare("INSERT INTO users(name,email,password_hash,track,role) VALUES(?,?,?,?,'student')").bind(name,email,hash,track).run(); const u=await env.DB.prepare('SELECT id,name,email,track,role,created_at FROM users WHERE id=?').bind(r.meta.last_row_id).first(); const token=await sign({id:u.id,exp:Math.floor(Date.now()/1000)+7*DAY},env.SESSION_SECRET); return json({user:safeUser(u)},201,{'set-cookie':setCookie(token)}); }
  catch(e){ return String(e).includes('UNIQUE')?fail('هذا البريد مسجل بالفعل.',409):fail('تعذر إنشاء الحساب حاليًا.',500); }
 }
 if (path === '/api/auth/login' && method === 'POST') {
  const b=await body(request), email=String(b.email||'').trim().toLowerCase(), password=String(b.password||'');
  const u=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
  if(!env.PASSWORD_PEPPER) return fail('إعداد الخادم ناقص: أضف السر PASSWORD_PEPPER في إعدادات Cloudflare Workers ثم أعد النشر.',500);
  if(!env.SESSION_SECRET) return fail('إعداد الخادم ناقص: أضف السر SESSION_SECRET في إعدادات Cloudflare Workers ثم أعد النشر.',500);
  if(!u || !(await checkPassword(password,u.password_hash,env.PASSWORD_PEPPER))) return fail('البريد الإلكتروني أو كلمة المرور غير صحيحة.',401);
  const token=await sign({id:u.id,exp:Math.floor(Date.now()/1000)+7*DAY},env.SESSION_SECRET);
  return json({user:safeUser(u)},200,{'set-cookie':setCookie(token)});
 }
 if (path === '/api/auth/logout' && method === 'POST') return json({ok:true},200,{'set-cookie':setCookie('',0)});
 if (path === '/api/auth/me' && method === 'GET') return user ? json({user:safeUser(user)}) : fail('الحساب غير مسجل الدخول.',401);
 if (path === '/api/admin/setup' && method === 'POST') {
  const b=await body(request);
  const admins=await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE role='admin'").first();
  if(admins.n>0) return fail('تم إنشاء حساب المدير بالفعل. استخدم صفحة تسجيل الدخول.',409);
  if(!env.ADMIN_SETUP_KEY || String(b.setupKey||'')!==env.ADMIN_SETUP_KEY) return fail('مفتاح الإعداد غير صحيح.',403);
  const name=String(b.name||'').trim(), email=String(b.email||'').trim().toLowerCase(), password=String(b.password||'');
  if(name.length<2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length<12) return fail('أدخل اسمًا وبريدًا صحيحًا وكلمة مرور لا تقل عن 12 حرفًا.');
  if(!env.PASSWORD_PEPPER) return fail('إعداد الخادم ناقص: أضف السر PASSWORD_PEPPER في إعدادات Cloudflare Workers ثم أعد النشر.',500);
  if(!env.SESSION_SECRET) return fail('إعداد الخادم ناقص: أضف السر SESSION_SECRET في إعدادات Cloudflare Workers ثم أعد النشر.',500);
  const hash=await hashPassword(password,env.PASSWORD_PEPPER);
  try { const r=await env.DB.prepare("INSERT INTO users(name,email,password_hash,track,role) VALUES(?,?,?,'thanaweya','admin')").bind(name,email,hash).run(); const u=await env.DB.prepare('SELECT id,name,email,track,role,created_at FROM users WHERE id=?').bind(r.meta.last_row_id).first(); const token=await sign({id:u.id,exp:Math.floor(Date.now()/1000)+7*DAY},env.SESSION_SECRET); return json({user:safeUser(u)},201,{'set-cookie':setCookie(token)}); } catch(e) { return fail(String(e).includes('UNIQUE')?'البريد مستخدم بالفعل.':'تعذر إنشاء حساب المدير.',409); }
 }
 const authErr=requireUser(user); if(authErr) return authErr;
 if(path==='/api/dashboard'&&method==='GET'){
  const tasks=await env.DB.prepare('SELECT COUNT(*) total, COALESCE(SUM(done),0) done FROM study_tasks WHERE user_id=?').bind(user.id).first();
  const attempts=await env.DB.prepare('SELECT COUNT(*) count, COALESCE(ROUND(AVG(score*100.0/total)),0) average FROM attempts WHERE user_id=?').bind(user.id).first();
  const points=await env.DB.prepare('SELECT points FROM contest_entries WHERE user_id=?').bind(user.id).first();
  return json({tasks,attempts,points:points?.points||0});
 }
 if(path==='/api/resources'&&method==='GET') return json({items:(await env.DB.prepare("SELECT id,subject,title,description,kind,url FROM resources WHERE track IN (?, 'both') ORDER BY subject,title").bind(user.track).all()).results});
 if(path==='/api/exams'&&method==='GET') { const qs=(await env.DB.prepare("SELECT id,subject,prompt,options_json FROM questions WHERE track IN (?, 'both') ORDER BY id").bind(user.track).all()).results; return json({questions:qs.map(q=>({...q,options:JSON.parse(q.options_json)}))}); }
 if(path==='/api/exams/submit'&&method==='POST'){
  const b=await body(request), answers=b.answers; if(!Array.isArray(answers)||!answers.length||answers.length>100) return fail('إجابات الامتحان غير صالحة.');
  const qs=(await env.DB.prepare("SELECT id,subject,correct_index,explanation FROM questions WHERE track IN (?, 'both')").bind(user.track).all()).results; const byId=new Map(qs.map(q=>[q.id,q])); let score=0,subject='اختبار عام',total=0; const details=[];
  for(const a of answers){const q=byId.get(Number(a.id));if(!q)continue;const correct=Number(a.choice)===q.correct_index;if(correct)score++;subject=q.subject;total++;details.push({id:q.id,correct,explanation:q.explanation});}
  if(!total)return fail('لم يتم العثور على أسئلة صالحة.');
  await env.DB.batch([env.DB.prepare('INSERT INTO attempts(user_id,subject,score,total) VALUES(?,?,?,?)').bind(user.id,subject,score,total),env.DB.prepare('INSERT INTO contest_entries(user_id,points) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET points=points+excluded.points,updated_at=CURRENT_TIMESTAMP').bind(user.id,score*10)]);
  return json({score,total,percent:Math.round(score*100/total),details});
 }
 if(path==='/api/tasks'&&method==='GET') return json({items:(await env.DB.prepare('SELECT id,title,subject,due_date,done,created_at FROM study_tasks WHERE user_id=? ORDER BY done,due_date,id DESC').bind(user.id).all()).results});
 if(path==='/api/tasks'&&method==='POST') { const b=await body(request),title=String(b.title||'').trim();if(title.length<2||title.length>160)return fail('اكتب اسم مهمة من حرفين إلى 160 حرفًا.');const r=await env.DB.prepare('INSERT INTO study_tasks(user_id,title,subject,due_date) VALUES(?,?,?,?)').bind(user.id,title,String(b.subject||'').slice(0,80),String(b.due_date||'').slice(0,10)).run();return json({item:await env.DB.prepare('SELECT id,title,subject,due_date,done FROM study_tasks WHERE id=?').bind(r.meta.last_row_id).first()},201); }
 let m=path.match(/^\/api\/tasks\/(\d+)$/); if(m&&method==='PATCH'){const b=await body(request),r=await env.DB.prepare('UPDATE study_tasks SET done=? WHERE id=? AND user_id=?').bind(b.done?1:0,Number(m[1]),user.id).run();return r.meta.changes?json({ok:true}):fail('المهمة غير موجودة.',404);}
 if(m&&method==='DELETE'){const r=await env.DB.prepare('DELETE FROM study_tasks WHERE id=? AND user_id=?').bind(Number(m[1]),user.id).run();return r.meta.changes?json({ok:true}):fail('المهمة غير موجودة.',404);}
 if(path==='/api/leaderboard'&&method==='GET'){const [items,contests]=await Promise.all([env.DB.prepare('SELECT u.name,c.points FROM contest_entries c JOIN users u ON u.id=c.user_id ORDER BY c.points DESC,c.updated_at ASC LIMIT 20').all(),env.DB.prepare("SELECT id,title,description,track,starts_at,ends_at FROM contests WHERE active=1 ORDER BY id DESC").all()]);return json({items:items.results,contests:contests.results});}
 if(path.startsWith('/api/admin/')) { const adminErr=requireAdmin(user); if(adminErr)return adminErr;
  if(path==='/api/admin/overview'&&method==='GET'){const [users,resources,questions]=await Promise.all([env.DB.prepare('SELECT COUNT(*) n FROM users WHERE role=\'student\'').first(),env.DB.prepare('SELECT COUNT(*) n FROM resources').first(),env.DB.prepare('SELECT COUNT(*) n FROM questions').first()]);return json({users:users.n,resources:resources.n,questions:questions.n});}
  if(path==='/api/admin/users'&&method==='GET')return json({items:(await env.DB.prepare('SELECT id,name,email,track,created_at FROM users WHERE role=\'student\' ORDER BY id DESC LIMIT 300').all()).results});
  if(path==='/api/admin/resources'&&method==='GET')return json({items:(await env.DB.prepare('SELECT * FROM resources ORDER BY id DESC').all()).results});
  if(path==='/api/admin/resources'&&method==='POST'){const b=await body(request),track=['thanaweya','bac2','both'].includes(b.track)?b.track:'both',subject=String(b.subject||'').trim(),title=String(b.title||'').trim();if(!subject||!title)return fail('المادة والعنوان مطلوبان.');const resourceUrl=String(b.url||'').trim();if(resourceUrl && !/^https?:\/\//i.test(resourceUrl))return fail('رابط المحتوى يجب أن يبدأ بـ https:// أو http://');const r=await env.DB.prepare('INSERT INTO resources(track,subject,title,description,kind,url) VALUES(?,?,?,?,?,?)').bind(track,subject,title,String(b.description||''),String(b.kind||'ملخص'),resourceUrl).run();return json({id:r.meta.last_row_id},201);}
  m=path.match(/^\/api\/admin\/resources\/(\d+)$/);if(m&&method==='DELETE'){await env.DB.prepare('DELETE FROM resources WHERE id=?').bind(Number(m[1])).run();return json({ok:true});}
  if(path==='/api/admin/questions'&&method==='GET')return json({items:(await env.DB.prepare('SELECT id,track,subject,prompt,options_json,correct_index,explanation FROM questions ORDER BY id DESC').all()).results.map(q=>({...q,options:JSON.parse(q.options_json)}))});
  if(path==='/api/admin/questions'&&method==='POST'){const b=await body(request),opts=Array.isArray(b.options)?b.options.map(x=>String(x).slice(0,300)):[];if(!b.subject||!b.prompt||opts.length<2||opts.length>6||!Number.isInteger(Number(b.correct_index))||Number(b.correct_index)<0||Number(b.correct_index)>=opts.length)return fail('راجع السؤال والاختيارات والإجابة الصحيحة.');const track=['thanaweya','bac2','both'].includes(b.track)?b.track:'both';const r=await env.DB.prepare('INSERT INTO questions(track,subject,prompt,options_json,correct_index,explanation) VALUES(?,?,?,?,?,?)').bind(track,String(b.subject),String(b.prompt),JSON.stringify(opts),Number(b.correct_index),String(b.explanation||'')).run();return json({id:r.meta.last_row_id},201);}
  m=path.match(/^\/api\/admin\/questions\/(\d+)$/);if(m&&method==='DELETE'){await env.DB.prepare('DELETE FROM questions WHERE id=?').bind(Number(m[1])).run();return json({ok:true});}
  if(path==='/api/admin/contests'&&method==='GET')return json({items:(await env.DB.prepare('SELECT id,title,description,track,starts_at,ends_at,active FROM contests ORDER BY id DESC').all()).results});
  if(path==='/api/admin/contests'&&method==='POST'){const b=await body(request),title=String(b.title||'').trim();if(!title)return fail('اسم المسابقة مطلوب.');const track=['thanaweya','bac2','both'].includes(b.track)?b.track:'both';const r=await env.DB.prepare('INSERT INTO contests(title,description,track,starts_at,ends_at,active) VALUES(?,?,?,?,?,?)').bind(title,String(b.description||''),track,String(b.starts_at||''),String(b.ends_at||''),b.active===false?0:1).run();return json({id:r.meta.last_row_id},201);}
  m=path.match(/^\/api\/admin\/contests\/(\d+)$/);if(m&&method==='DELETE'){await env.DB.prepare('DELETE FROM contests WHERE id=?').bind(Number(m[1])).run();return json({ok:true});}
  return fail('المسار الإداري غير موجود.',404);
 }
 return fail('المسار غير موجود.',404);
}
export default { async fetch(request, env) { const url=new URL(request.url); if(url.pathname.startsWith('/api/')) { try { return await handleApi(request,env); } catch(e) { console.error('Sanad API error',e); return fail('حدث خطأ داخلي. حاول مرة أخرى.',500); } } return env.ASSETS.fetch(request); } };
