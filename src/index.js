/**
 * Cloudflare Workers — 文件存储 + 用户系统 + 云函数 + 密码下载
 *
 * 功能：
 *   - 用户注册/登录（Session Cookie + KV）
 *   - 按用户隔离的多级目录文件存储
 *   - 密码保护下载
 *   - JS 沙箱执行（云函数，基于 QuickJS WASM）
 *   - 使用文档
 */

import createQuickJS from './qjs_wasm.js';
import wasmModule from './qjs_wasm.wasm';

// ==================== QuickJS WASM 初始化 ====================

/** 全局 QuickJS 实例，首次调用时初始化 */
let _qjsModule = null;
let _qjsInitPromise = null;

function getQJS() {
  if (_qjsModule) return _qjsModule;
  if (!_qjsInitPromise) {
    // Cloudflare Workers 中 self.location 可能不存在，补一个假对象防止 Emscripten 环境检测崩溃
    if (typeof self !== 'undefined' && !self.location) {
      self.location = { href: 'https://localhost/' };
    }
    _qjsInitPromise = createQuickJS({
      // 通过 ES 模块静态导入的 WASM 模块实例化，绕过 Cloudflare 的动态 WASM 编译限制
      instantiateWasm: function(imports, successCallback) {
        WebAssembly.instantiate(wasmModule, imports).then(
          function(instance) { successCallback(instance); },
          function(err) { console.error('WASM 实例化失败:', err); }
        );
        return {};
      }
    }).then(function(mod) {
      _qjsModule = mod;
      return mod;
    });
  }
  return _qjsInitPromise;
}

/**
 * 调用 QuickJS eval_js（无参数）
 * @param {string} code - JS 代码
 * @returns {{output: string[], result: any}}
 */
function qjsEval(code) {
  const mod = _qjsModule;
  const codeLen = mod.lengthBytesUTF8(code) + 1;
  const codePtr = mod._malloc(codeLen);
  mod.stringToUTF8(code, codePtr, codeLen);
  const resultPtr = mod._eval_js(codePtr);
  mod._free(codePtr);
  const resultJson = mod.UTF8ToString(resultPtr);
  mod._free(resultPtr);
  return JSON.parse(resultJson);
}

/**
 * 调用 QuickJS eval_js_with_params（带参数）
 * @param {string} code - JS 代码
 * @param {object} params - 参数对象，会以 params 变量注入沙箱
 * @returns {{output: string[], result: any}}
 */
function qjsEvalWithParams(code, params) {
  const mod = _qjsModule;
  const paramsJson = JSON.stringify(params || {});
  const codeLen = mod.lengthBytesUTF8(code) + 1;
  const paramsLen = mod.lengthBytesUTF8(paramsJson) + 1;
  const codePtr = mod._malloc(codeLen);
  const paramsPtr = mod._malloc(paramsLen);
  mod.stringToUTF8(code, codePtr, codeLen);
  mod.stringToUTF8(paramsJson, paramsPtr, paramsLen);
  const resultPtr = mod._eval_js_with_params(codePtr, paramsPtr);
  mod._free(codePtr);
  mod._free(paramsPtr);
  const resultJson = mod.UTF8ToString(resultPtr);
  mod._free(resultPtr);
  return JSON.parse(resultJson);
}

// ==================== 工具函数 ====================

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64ToText(base64) {
  return new TextDecoder().decode(base64ToBytes(base64));
}

/** SHA-256 哈希（用于密码） */
async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** 生成随机 Token */
function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** 判断是否为纯文本文件 */
function isTextFile(filename, contentType) {
  if (contentType && (contentType.startsWith('text/') || contentType === 'application/json' || contentType === 'application/xml' || contentType === 'application/javascript')) return true;
  const ext = filename.substring(filename.lastIndexOf('.')).toLowerCase();
  return ['.txt','.md','.json','.xml','.html','.css','.js','.ts','.py','.java','.c','.cpp','.h','.rs','.go','.yaml','.yml','.toml','.ini','.cfg','.conf','.log','.csv','.sh','.bat','.ps1','.sql','.rb','.php','.swift','.kt','.lua','.r','.pl','.scala','.dart','.tex','.svg'].includes(ext);
}

function isImageFile(filename, contentType) {
  if (contentType && contentType.startsWith('image/')) return true;
  return ['.png','.jpg','.jpeg','.gif','.webp','.svg','.bmp','.ico'].includes(filename.substring(filename.lastIndexOf('.')).toLowerCase());
}

function normalizeDir(dir) {
  if (!dir) return '';
  return dir.replace(/\\/g, '/').replace(/\/+/g, '/').replace(/^\/+|\/+$/g, '');
}

function sanitizeSegment(seg) {
  return seg.replace(/[\/\\\x00-\x1f]/g, '_');
}

function makeFileKey(userId, dir, filename, timestamp) {
  const cleanDir = normalizeDir(dir);
  const cleanName = sanitizeSegment(filename) + '_' + timestamp;
  return userId + '/' + (cleanDir ? cleanDir + '/' : '') + cleanName;
}

function parseRoute(pathname) {
  const m = pathname.match(/^\/api\/files\/(.+)\/download$/);
  if (m) return { type: 'download', key: m[1] };
  const m2 = pathname.match(/^\/api\/files\/(.+)$/);
  if (m2) return { type: 'file', key: m2[1] };
  return null;
}

// ==================== 认证中间件 ====================

/** 支持 Session Cookie 和 Bearer Token（API Key）两种认证，返回用户信息+权限+管理员标记 */
async function auth(request, env) {
  // 1. Session Cookie
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/session=([^;]+)/);
  if (match) {
    const data = await env.FILE_STORE.get('session:' + match[1], 'json');
    if (data) {
      const isAdmin = !!(await env.FILE_STORE.get('admin:' + data.userId));
      return { username: data.username, userId: data.userId, perms: null, isAdmin }; // session 全权限
    }
  }

  // 2. Bearer Token (API Key)
  const authHeader = request.headers.get('Authorization') || '';
  const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
  if (bearerMatch) {
    const apiKey = bearerMatch[1];
    const keyData = await env.FILE_STORE.get('apikey_lookup:' + apiKey, 'json');
    if (keyData) {
      return { username: keyData.username, userId: keyData.userId, perms: keyData.permissions, isAdmin: false };
    }
  }

  return null;
}

/** 检查权限 */
function checkPerm(user, action) {
  if (!user) return false;
  if (user.perms === null) return true; // Session 登录有全部权限
  const permMap = {
    'files:read': ['files:read'],
    'files:write': ['files:write'],
    'files:delete': ['files:delete'],
    'files:edit': ['files:edit'],
    'scripts:read': ['scripts:read'],
    'scripts:write': ['scripts:write'],
    'scripts:execute': ['scripts:execute'],
  };
  const required = permMap[action];
  if (!required) return false;
  return required.some(p => user.perms.includes(p));
}

// ==================== HTML 页面 ====================

const HTML_LOGIN = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 - 文件存储</title>
<style>
  :root { --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3; --text-dim:#8b949e; --accent:#58a6ff; --accent-hover:#79c0ff; --danger:#f85149; --success:#3fb950; --radius:8px; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; display:flex; align-items:center; justify-content:center; }
  .card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:32px; width:100%; max-width:380px; }
  .card h1 { text-align:center; font-size:1.4rem; margin-bottom:4px; }
  .card p { text-align:center; color:var(--text-dim); font-size:0.8rem; margin-bottom:20px; }
  .tabs { display:flex; margin-bottom:20px; border-bottom:1px solid var(--border); }
  .tabs button { flex:1; padding:8px; background:none; border:none; color:var(--text-dim); cursor:pointer; font-size:0.9rem; border-bottom:2px solid transparent; }
  .tabs button.active { color:var(--accent); border-bottom-color:var(--accent); }
  .field { margin-bottom:14px; }
  .field label { display:block; font-size:0.8rem; color:var(--text-dim); margin-bottom:4px; }
  .field input { width:100%; padding:8px 12px; border-radius:6px; border:1px solid var(--border); background:var(--bg); color:var(--text); font-size:0.9rem; outline:none; }
  .field input:focus { border-color:var(--accent); }
  .btn { width:100%; padding:10px; border-radius:var(--radius); border:none; background:var(--accent); color:#fff; cursor:pointer; font-size:0.9rem; margin-top:6px; }
  .btn:hover { background:var(--accent-hover); }
  .error { color:var(--danger); font-size:0.8rem; text-align:center; margin-top:8px; }
  .success { color:var(--success); font-size:0.8rem; text-align:center; margin-top:8px; }
  .hidden { display:none !important; }
</style>
</head>
<body>
<div class="card">
  <h1>文件存储</h1>
  <p>注册后即可使用</p>
  <div class="tabs">
    <button id="tabLogin" class="active">登录</button>
    <button id="tabRegister">注册</button>
  </div>
  <div id="formLogin">
    <div class="field"><label>用户名</label><input type="text" id="loginUser" placeholder="输入用户名"></div>
    <div class="field"><label>密码</label><input type="password" id="loginPass" placeholder="输入密码"></div>
    <button class="btn" id="btnLogin">登录</button>
  </div>
  <div id="formRegister" class="hidden">
    <div class="field"><label>用户名</label><input type="text" id="regUser" placeholder="3-20位字母数字"></div>
    <div class="field"><label>密码</label><input type="password" id="regPass" placeholder="至少6位"></div>
    <div class="field"><label>确认密码</label><input type="password" id="regPass2" placeholder="再次输入密码"></div>
    <button class="btn" id="btnRegister">注册</button>
  </div>
  <div class="error hidden" id="authError"></div>
  <div class="success hidden" id="authSuccess"></div>
</div>
<script>
const tabLogin=document.getElementById('tabLogin'),tabRegister=document.getElementById('tabRegister');
const formLogin=document.getElementById('formLogin'),formRegister=document.getElementById('formRegister');
const authError=document.getElementById('authError'),authSuccess=document.getElementById('authSuccess');
tabLogin.addEventListener('click',()=>{tabLogin.classList.add('active');tabRegister.classList.remove('active');formLogin.classList.remove('hidden');formRegister.classList.add('hidden');authError.classList.add('hidden');authSuccess.classList.add('hidden')});
tabRegister.addEventListener('click',()=>{tabRegister.classList.add('active');tabLogin.classList.remove('active');formRegister.classList.remove('hidden');formLogin.classList.add('hidden');authError.classList.add('hidden');authSuccess.classList.add('hidden')});

async function post(url,body){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return r.json()}

document.getElementById('btnLogin').addEventListener('click',async()=>{
  const username=document.getElementById('loginUser').value.trim(),password=document.getElementById('loginPass').value;
  if(!username||!password){authError.textContent='请填写所有字段';authError.classList.remove('hidden');return}
  const d=await post('/api/auth/login',{username,password});
  if(d.error){authError.textContent=d.error;authError.classList.remove('hidden');authSuccess.classList.add('hidden')}
  else {authSuccess.textContent='登录成功，跳转中...';authSuccess.classList.remove('hidden');authError.classList.add('hidden');setTimeout(()=>location.href='/',800)}
});

document.getElementById('btnRegister').addEventListener('click',async()=>{
  const username=document.getElementById('regUser').value.trim(),password=document.getElementById('regPass').value,password2=document.getElementById('regPass2').value;
  if(!username||!password){authError.textContent='请填写所有字段';authError.classList.remove('hidden');return}
  if(!/^[a-zA-Z0-9]{3,20}$/.test(username)){authError.textContent='用户名需3-20位字母或数字';authError.classList.remove('hidden');return}
  if(password.length<6){authError.textContent='密码至少6位';authError.classList.remove('hidden');return}
  if(password!==password2){authError.textContent='两次密码不一致';authError.classList.remove('hidden');return}
  const d=await post('/api/auth/register',{username,password});
  if(d.error){authError.textContent=d.error;authError.classList.remove('hidden');authSuccess.classList.add('hidden')}
  else {authSuccess.textContent='注册成功，请登录';authSuccess.classList.remove('hidden');authError.classList.add('hidden');tabLogin.click()}
});
</script>
</body>
</html>`;

const HTML_SETUP = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>系统安装 - 文件存储</title>
<style>
  :root { --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3; --text-dim:#8b949e; --accent:#58a6ff; --accent-hover:#79c0ff; --danger:#f85149; --success:#3fb950; --radius:8px; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; display:flex; align-items:center; justify-content:center; }
  .card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:32px; width:100%; max-width:420px; }
  .card h1 { text-align:center; font-size:1.4rem; margin-bottom:4px; color:var(--accent); }
  .card .sub { text-align:center; color:var(--text-dim); font-size:0.8rem; margin-bottom:20px; }
  .card .info { background:rgba(88,166,255,0.08); border:1px solid rgba(88,166,255,0.2); border-radius:6px; padding:10px 12px; font-size:0.78rem; color:var(--text-dim); margin-bottom:18px; line-height:1.6; }
  .field { margin-bottom:14px; }
  .field label { display:block; font-size:0.8rem; color:var(--text-dim); margin-bottom:4px; }
  .field input { width:100%; padding:8px 12px; border-radius:6px; border:1px solid var(--border); background:var(--bg); color:var(--text); font-size:0.9rem; outline:none; }
  .field input:focus { border-color:var(--accent); }
  .btn { width:100%; padding:10px; border-radius:var(--radius); border:none; background:var(--accent); color:#fff; cursor:pointer; font-size:0.9rem; margin-top:6px; }
  .btn:hover { background:var(--accent-hover); }
  .error { color:var(--danger); font-size:0.8rem; text-align:center; margin-top:8px; }
  .success { color:var(--success); font-size:0.8rem; text-align:center; margin-top:8px; }
  .hidden { display:none !important; }
</style>
</head>
<body>
<div class="card">
  <h1>系统安装</h1>
  <p class="sub">首次使用，请创建管理员账号</p>
  <div class="info">管理员账号拥有最高权限，可以查看所有用户的文件、云函数，并进行审查管理。</div>
  <div class="field"><label>管理员用户名</label><input type="text" id="setupUser" placeholder="3-20位字母数字"></div>
  <div class="field"><label>密码</label><input type="password" id="setupPass" placeholder="至少6位"></div>
  <div class="field"><label>确认密码</label><input type="password" id="setupPass2" placeholder="再次输入密码"></div>
  <button class="btn" id="btnSetup">安装</button>
  <div class="error hidden" id="setupError"></div>
  <div class="success hidden" id="setupSuccess"></div>
</div>
<script>
document.getElementById('btnSetup').addEventListener('click',async()=>{
  const username=document.getElementById('setupUser').value.trim();
  const password=document.getElementById('setupPass').value;
  const password2=document.getElementById('setupPass2').value;
  const err=document.getElementById('setupError'),suc=document.getElementById('setupSuccess');
  err.classList.add('hidden');suc.classList.add('hidden');
  if(!username||!password){err.textContent='请填写所有字段';err.classList.remove('hidden');return}
  if(!/^[a-zA-Z0-9]{3,20}$/.test(username)){err.textContent='用户名需3-20位字母或数字';err.classList.remove('hidden');return}
  if(password.length<6){err.textContent='密码至少6位';err.classList.remove('hidden');return}
  if(password!==password2){err.textContent='两次密码不一致';err.classList.remove('hidden');return}
  try{
    const r=await fetch('/api/admin/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
    const d=await r.json();
    if(d.error){err.textContent=d.error;err.classList.remove('hidden')}
    else {suc.textContent='安装成功！跳转中...';suc.classList.remove('hidden');setTimeout(()=>location.href='/',800)}
  }catch(e){err.textContent='网络错误';err.classList.remove('hidden')}
});
</script>
</body>
</html>`;

const HTML_APP = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>文件存储</title>
<style>
  :root { --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3; --text-dim:#8b949e; --accent:#58a6ff; --accent-hover:#79c0ff; --danger:#f85149; --success:#3fb950; --warning:#d29922; --radius:8px; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; }
  .topbar { display:flex; align-items:center; padding:10px 18px; background:var(--surface); border-bottom:1px solid var(--border); gap:14px; }
  .topbar .brand { font-weight:700; font-size:1rem; color:var(--accent); }
  .topbar nav { display:flex; gap:4px; }
  .topbar nav a { padding:5px 12px; border-radius:6px; color:var(--text-dim); text-decoration:none; font-size:0.85rem; cursor:pointer; }
  .topbar nav a:hover, .topbar nav a.active { color:var(--text); background:rgba(255,255,255,0.05); }
  .topbar .spacer { flex:1; }
  .topbar .user { color:var(--text-dim); font-size:0.82rem; }
  .topbar .logout { color:var(--accent); cursor:pointer; font-size:0.82rem; background:none; border:none; }
  .container { max-width:1000px; margin:0 auto; padding:16px; }
  .page { display:none; }
  .page.active { display:block; }
  .breadcrumb { display:flex; align-items:center; gap:6px; margin-bottom:14px; flex-wrap:wrap; font-size:0.85rem; }
  .breadcrumb a { color:var(--accent); text-decoration:none; cursor:pointer; }
  .breadcrumb a:hover { text-decoration:underline; }
  .breadcrumb span { color:var(--text-dim); }
  .breadcrumb .current { color:var(--text); font-weight:600; }
  .toolbar { display:flex; gap:8px; margin-bottom:12px; flex-wrap:wrap; align-items:center; }
  .toolbar .spacer { flex:1; }
  .search-box { padding:6px 10px; border-radius:var(--radius); border:1px solid var(--border); background:var(--surface); color:var(--text); font-size:0.82rem; outline:none; min-width:160px; }
  .search-box:focus { border-color:var(--accent); }
  .btn { padding:6px 12px; border-radius:var(--radius); border:1px solid var(--border); background:var(--surface); color:var(--text); cursor:pointer; font-size:0.8rem; transition:all .15s; white-space:nowrap; }
  .btn:hover { border-color:var(--text-dim); }
  .btn-accent { background:var(--accent); border-color:var(--accent); color:#fff; }
  .btn-accent:hover { background:var(--accent-hover); }
  .btn-danger { background:var(--danger); border-color:var(--danger); color:#fff; }
  .btn-danger:hover { background:#ff6b63; }
  .btn-sm { padding:3px 8px; font-size:0.75rem; }
  .file-list { border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; }
  .file-item { display:flex; align-items:center; gap:10px; padding:9px 14px; border-bottom:1px solid var(--border); transition:background .15s; }
  .file-item:last-child { border-bottom:none; }
  .file-item:hover { background:var(--surface); }
  .file-item.dir { cursor:pointer; }
  .file-icon { width:30px; height:30px; border-radius:6px; display:flex; align-items:center; justify-content:center; font-size:0.9rem; flex-shrink:0; }
  .file-info { flex:1; min-width:0; }
  .file-name { font-size:0.85rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .file-name a { color:var(--text); text-decoration:none; cursor:pointer; }
  .file-name a:hover { color:var(--accent); }
  .file-meta { font-size:0.7rem; color:var(--text-dim); display:flex; gap:8px; }
  .size-sm { color:var(--success); } .size-md { color:var(--warning); } .size-lg { color:var(--danger); }
  .file-actions { display:flex; gap:3px; flex-shrink:0; }
  .lock-icon { color:var(--warning); margin-left:4px; }
  .empty-state { padding:48px 20px; text-align:center; color:var(--text-dim); }
  .modal-overlay { position:fixed; inset:0; background:rgba(0,0,0,0.7); display:flex; align-items:center; justify-content:center; z-index:100; padding:16px; }
  .modal { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); width:100%; max-width:860px; max-height:88vh; display:flex; flex-direction:column; }
  .modal-header { display:flex; align-items:center; justify-content:space-between; padding:10px 14px; border-bottom:1px solid var(--border); }
  .modal-header h3 { font-size:0.9rem; }
  .modal-body { flex:1; padding:10px 14px; overflow:auto; }
  .modal textarea { width:100%; min-height:300px; max-height:55vh; padding:10px; border-radius:6px; border:1px solid var(--border); background:var(--bg); color:var(--text); font-family:'Cascadia Code','Consolas',monospace; font-size:0.8rem; line-height:1.5; resize:vertical; outline:none; }
  .modal textarea:focus { border-color:var(--accent); }
  .modal-footer { display:flex; justify-content:flex-end; gap:8px; padding:8px 14px; border-top:1px solid var(--border); }
  .modal input { width:100%; padding:8px 12px; border-radius:6px; border:1px solid var(--border); background:var(--bg); color:var(--text); font-size:0.85rem; outline:none; }
  .modal input:focus { border-color:var(--accent); }
  .modal label { display:block; font-size:0.8rem; color:var(--text-dim); margin-bottom:4px; margin-top:10px; }
  .preview-overlay { position:fixed; inset:0; background:rgba(0,0,0,0.85); display:flex; align-items:center; justify-content:center; z-index:100; padding:20px; cursor:pointer; }
  .preview-overlay img { max-width:90vw; max-height:85vh; object-fit:contain; border-radius:4px; }
  .preview-overlay .close-btn { position:absolute; top:16px; right:20px; color:#fff; font-size:1.5rem; cursor:pointer; }
  .toast { position:fixed; bottom:24px; right:24px; padding:10px 18px; border-radius:var(--radius); background:var(--surface); border:1px solid var(--border); color:var(--text); font-size:0.8rem; z-index:200; animation:fadeIn .2s; }
  .toast.success { border-color:var(--success); }
  .toast.error { border-color:var(--danger); }
  @keyframes fadeIn { from { opacity:0; transform:translateY(8px); } }
  .hidden { display:none !important; }
  /* 脚本列表 */
  .script-list { display:grid; gap:10px; }
  .script-card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:14px; cursor:pointer; transition:border-color .15s; }
  .script-card:hover { border-color:var(--accent); }
  .script-card h4 { font-size:0.9rem; margin-bottom:4px; }
  .script-card p { font-size:0.75rem; color:var(--text-dim); }
  .run-output { background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:10px; font-family:monospace; font-size:0.8rem; max-height:200px; overflow:auto; white-space:pre-wrap; margin-top:10px; }
  .run-output.error { color:var(--danger); }
  .run-output.success { color:var(--success); }
  /* 文档 */
  .docs h2 { font-size:1.1rem; margin:20px 0 8px; }
  .docs h3 { font-size:0.95rem; margin:14px 0 6px; }
  .docs p, .docs li { font-size:0.85rem; color:var(--text-dim); line-height:1.7; }
  .docs code { background:var(--surface); padding:1px 5px; border-radius:4px; font-size:0.8rem; }
  .docs pre { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:12px; overflow:auto; font-size:0.8rem; margin:8px 0; }
  .docs ul { padding-left:20px; }
</style>
</head>
<body>
<div class="topbar">
  <span class="brand">文件存储</span>
  <nav>
    <a data-page="files" class="active">文件</a>
    <a data-page="scripts">云函数</a>
    <a data-page="apikeys">API Key</a>
    <a data-page="docs">文档</a>
    <!-- ADMIN_NAV -->
  </nav>
  <span class="spacer"></span>
  <span class="user" id="userDisplay"></span>
  <button class="logout" id="btnLogout">退出</button>
</div>
<div class="container">
  <!-- 文件页 -->
  <div class="page active" id="pageFiles">
    <div class="breadcrumb" id="breadcrumb"></div>
    <div class="toolbar">
      <button class="btn btn-accent" id="uploadBtn">上传文件</button>
      <button class="btn" id="mkdirBtn">新建目录</button>
      <span class="spacer"></span>
      <input type="text" class="search-box" id="searchBox" placeholder="搜索...">
      <button class="btn btn-sm" id="refreshBtn">刷新</button>
    </div>
    <div class="file-list" id="fileList"><div class="empty-state">加载中...</div></div>
  </div>
  <!-- 云函数页 -->
  <div class="page" id="pageScripts">
    <div class="toolbar">
      <button class="btn btn-accent" id="newScriptBtn">新建脚本</button>
      <span class="spacer"></span>
      <button class="btn btn-sm" id="refreshScriptsBtn">刷新</button>
    </div>
    <div class="script-list" id="scriptList"></div>
  </div>
  <!-- API Key 页 -->
  <div class="page" id="pageApikeys">
    <div class="toolbar">
      <button class="btn btn-accent" id="createApiKeyBtn">创建 API Key</button>
      <span class="spacer"></span>
      <button class="btn btn-sm" id="refreshApiKeysBtn">刷新</button>
    </div>
    <div class="file-list" id="apiKeyList"><div class="empty-state">加载中...</div></div>
  </div>
  <!-- 文档页 -->
  <div class="page docs" id="pageDocs">
    <h2>使用文档</h2>
    <h3>文件管理</h3>
    <ul>
      <li>上传文件时可指定目标目录（如 <code>docs/notes</code>），支持多级目录</li>
      <li>上传时可设置密码保护下载，密码使用 SHA-256 哈希存储</li>
      <li>文本文件支持在线编辑，快捷键 <code>Ctrl+S</code> 保存</li>
      <li>图片文件点击文件名可直接预览，按 <code>ESC</code> 关闭</li>
      <li>支持拖拽上传，文件以 Base64 编码无损存入 KV</li>
    </ul>
    <h3>云函数（JS 沙箱）</h3>
    <ul>
      <li>编写 JavaScript 代码并在线执行，基于 QuickJS WASM 安全沙箱</li>
      <li>支持 <strong>async/await</strong> 语法</li>
      <li>支持传入参数：在参数输入框中填写 JSON，代码中通过 <code>params</code> 变量访问</li>
      <li>输出通过 <code>console.log()</code> 捕获，返回值显示在结果区</li>
      <li>可用全局对象：<code>Math</code>、<code>Date</code>、<code>JSON</code>、<code>Array</code>、<code>Object</code>、<code>String</code>、<code>Number</code>、<code>parseInt</code>、<code>parseFloat</code></li>
      <li>文件操作对象 <code>storage</code>：</li>
    </ul>
    <pre>// 列出目录
const files = await storage.listFiles('docs');
// 读取文件
const content = await storage.readFile('docs/notes.txt');
// 写入文件
await storage.writeFile('output.txt', '新内容');
// 删除文件
await storage.deleteFile('old.txt');
// 获取下载信息
const info = await storage.downloadFile('report.pdf');
console.log(info.url, info.name);</pre>
    <ul>
      <li>沙箱环境：无网络访问（<code>fetch</code> 不可用），无定时器</li>
      <li>执行时间受 Worker CPU 限制，超时将自动终止</li>
      <li>返回值会显示在输出区域</li>
    </ul>
    <h3>管理员系统</h3>
    <ul>
      <li>首次访问系统时进入安装页面，创建管理员账号</li>
      <li>管理员可查看所有用户、文件、云函数</li>
      <li>管理员可审查并删除任意用户的文件或云函数</li>
    </ul>
    <h3>API 接口</h3>
    <pre># 列出文件（需登录 Cookie）
GET /api/files?dir=path

# 上传文件
POST /api/upload
Content-Type: multipart/form-data
字段: file, dir, password

# 下载文件（密码文件需 ?password=xxx）
GET /api/files/:key/download?password=xxx

# 获取文件内容
GET /api/files/:key

# 更新文本文件
PUT /api/files/:key
{"content": "新内容"}

# 删除文件
DELETE /api/files/:key

# 创建目录
POST /api/mkdir
{"dir": "path"}

# 执行云函数
POST /api/run
{"code": "console.log('hello')"}
# 带参数
POST /api/run
{"code": "console.log(params.a)", "params": {"a": 1}}
# 获取脚本列表
GET /api/scripts
# 创建/更新脚本
POST /api/scripts
{"name": "名称", "code": "..."}
# 执行已保存脚本
POST /api/scripts/:id/run
{"params": {"a": 1}}   # 参数可选</pre>
    <h3>API Key 认证</h3>
    <ul>
      <li>在"API Key"页面创建 Key，勾选需要的权限</li>
      <li>每个用户最多创建 3 个 API Key</li>
      <li>通过 HTTP Header <code>Authorization: Bearer &lt;你的APIKey&gt;</code> 使用</li>
    </ul>
    <pre># 示例：用 API Key 上传文件
curl -X POST https://file-text-store.difierline.workers.dev/api/upload \
  -H "Authorization: Bearer ak_xxxxxxxxxxxx" \
  -F "file=@test.txt" \
  -F "dir=docs"

# 示例：用 API Key 执行云函数
curl -X POST https://file-text-store.difierline.workers.dev/api/run \
  -H "Authorization: Bearer ak_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{"code":"console.log(\"hello\")","params":{"a":1}}'</pre>
    <h3>存储说明</h3>
    <ul>
      <li>使用 Cloudflare Workers KV 存储，数据最终一致性</li>
      <li>单文件最大 25MB（KV 限制）</li>
      <li>免费额度：每天 10 万次读取 + 1000 次写入/删除</li>
      <li>密码使用 SHA-256 哈希存储，不保存明文</li>
    </ul>
  </div>
  <!-- 管理页（仅管理员可见） -->
  <div class="page" id="pageAdmin">
    <div class="toolbar">
      <button class="btn btn-accent" id="adminTabUsers">用户</button>
      <button class="btn" id="adminTabFiles">文件</button>
      <button class="btn" id="adminTabScripts">脚本</button>
      <span class="spacer"></span>
      <input type="text" class="search-box" id="adminSearchBox" placeholder="搜索...">
      <button class="btn btn-sm" id="adminRefreshBtn">刷新</button>
    </div>
    <div class="file-list" id="adminList"><div class="empty-state">加载中...</div></div>
  </div>
</div>

<!-- 上传弹窗 -->
<div class="modal-overlay hidden" id="uploadDialog">
  <div class="modal">
    <div class="modal-header"><h3>上传文件</h3><button class="btn btn-sm" id="uploadDialogClose">✕</button></div>
    <div class="modal-body">
      <label>目标目录</label><input type="text" id="uploadDir" placeholder="留空=根目录">
      <label>下载密码（可选）</label><input type="text" id="uploadPassword" placeholder="留空=无需密码">
      <label>选择文件</label><div style="font-size:0.8rem;color:var(--success);margin-top:4px" id="uploadFileNames">未选择文件</div>
      <div class="hidden" id="uploadProgressWrap" style="margin-top:8px">
        <div style="font-size:0.75rem;color:var(--text-dim);margin-bottom:4px" id="uploadProgressText"></div>
        <div class="progress" style="height:4px;background:var(--border);border-radius:2px;overflow:hidden"><div id="uploadProgressBar" style="height:100%;background:var(--accent);transition:width .2s;width:0%"></div></div>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn" id="uploadDialogCancel">取消</button>
      <button class="btn btn-accent" id="uploadDialogConfirm">上传</button>
    </div>
  </div>
</div>

<!-- 编辑弹窗 -->
<div class="modal-overlay hidden" id="editModal">
  <div class="modal">
    <div class="modal-header"><h3 id="editModalTitle">编辑</h3><button class="btn btn-sm" id="editModalClose">✕</button></div>
    <div class="modal-body"><textarea id="editTextarea"></textarea></div>
    <div class="modal-footer"><button class="btn" id="editModalCancel">取消</button><button class="btn btn-accent" id="editModalSave">保存</button></div>
  </div>
</div>

<!-- 图片预览 -->
<div class="preview-overlay hidden" id="imgPreview"><span class="close-btn" id="imgPreviewClose">✕</span><img id="imgPreviewImg" src=""></div>

<!-- 密码弹窗 -->
<div class="modal-overlay hidden" id="pwdDialog">
  <div class="modal" style="max-width:360px">
    <div class="modal-header"><h3>输入下载密码</h3></div>
    <div class="modal-body"><input type="password" id="pwdInput" placeholder="请输入密码"></div>
    <div class="modal-footer"><button class="btn" id="pwdCancel">取消</button><button class="btn btn-accent" id="pwdConfirm">确认</button></div>
  </div>
</div>

<!-- 脚本编辑器弹窗 -->
<div class="modal-overlay hidden" id="scriptModal">
  <div class="modal">
    <div class="modal-header"><h3 id="scriptModalTitle">脚本</h3><button class="btn btn-sm" id="scriptModalClose">✕</button></div>
    <div class="modal-body">
      <label>名称</label><input type="text" id="scriptName" placeholder="脚本名称">
      <label>代码</label><textarea id="scriptCode" style="min-height:200px" placeholder="console.log('hello');"></textarea>
      <label>参数（JSON，可选）</label><input type="text" id="scriptParams" placeholder='{"key": "value"}' style="font-size:0.8rem">
      <div class="run-output hidden" id="runOutput"></div>
    </div>
    <div class="modal-footer">
      <button class="btn" id="scriptModalCancel">取消</button>
      <button class="btn btn-accent" id="scriptRun">运行</button>
      <button class="btn btn-accent" id="scriptSave">保存</button>
    </div>
  </div>
</div>

<!-- API Key 创建弹窗 -->
<div class="modal-overlay hidden" id="apiKeyModal">
  <div class="modal" style="max-width:500px">
    <div class="modal-header"><h3>创建 API Key</h3><button class="btn btn-sm" id="apiKeyModalClose">✕</button></div>
    <div class="modal-body">
      <label>名称</label><input type="text" id="apiKeyName" placeholder="例如: 上传专用">
      <label style="margin-top:12px">权限</label>
      <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:4px">
        <label style="display:flex;align-items:center;gap:4px;font-size:0.82rem;cursor:pointer"><input type="checkbox" value="files:read"> 读取文件</label>
        <label style="display:flex;align-items:center;gap:4px;font-size:0.82rem;cursor:pointer"><input type="checkbox" value="files:write"> 上传文件</label>
        <label style="display:flex;align-items:center;gap:4px;font-size:0.82rem;cursor:pointer"><input type="checkbox" value="files:delete"> 删除文件</label>
        <label style="display:flex;align-items:center;gap:4px;font-size:0.82rem;cursor:pointer"><input type="checkbox" value="files:edit"> 编辑文件</label>
        <label style="display:flex;align-items:center;gap:4px;font-size:0.82rem;cursor:pointer"><input type="checkbox" value="scripts:read"> 读取脚本</label>
        <label style="display:flex;align-items:center;gap:4px;font-size:0.82rem;cursor:pointer"><input type="checkbox" value="scripts:write"> 创建脚本</label>
        <label style="display:flex;align-items:center;gap:4px;font-size:0.82rem;cursor:pointer"><input type="checkbox" value="scripts:execute"> 执行脚本</label>
      </div>
      <div id="apiKeyResult" class="hidden" style="margin-top:12px;padding:10px;background:var(--bg);border:1px solid var(--success);border-radius:6px;word-break:break-all">
        <div style="font-size:0.8rem;color:var(--success);margin-bottom:4px">API Key 已创建（仅显示一次）:</div>
        <code style="font-size:0.75rem;color:var(--accent)" id="apiKeyValue"></code>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn" id="apiKeyModalCancel">取消</button>
      <button class="btn btn-accent" id="apiKeyCreate">创建</button>
    </div>
  </div>
</div>

<div id="toastContainer"></div>

<script>
const API='/api/files',AUTH='/api/auth';
let currentDir='',allEntries=[],pendingFiles=null,editingKey=null,pwdResolve=null;

function toast(m,t){const e=document.createElement('div');e.className='toast '+t;e.textContent=m;document.getElementById('toastContainer').appendChild(e);setTimeout(()=>e.remove(),2800)}
function formatSize(b){if(!b)return'';if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';return(b/1048576).toFixed(1)+' MB'}

// ========== 页面切换 ==========
document.querySelectorAll('[data-page]').forEach(a=>{a.addEventListener('click',()=>{document.querySelectorAll('[data-page]').forEach(x=>x.classList.remove('active'));a.classList.add('active');document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));document.getElementById('page'+a.dataset.page.charAt(0).toUpperCase()+a.dataset.page.slice(1)).classList.add('active');if(a.dataset.page==='scripts')loadScripts();if(a.dataset.page==='apikeys')loadApiKeys();if(a.dataset.page==='files')loadEntries();if(a.dataset.page==='admin')loadAdminData()})});

// ========== 退出 ==========
document.getElementById('btnLogout').addEventListener('click',async()=>{await fetch(AUTH+'/logout',{method:'POST'});location.reload()});

// ========== 文件列表 ==========
async function loadEntries(){
  try{const p=new URLSearchParams();if(currentDir)p.set('dir',currentDir);const r=await fetch(API+'?'+p.toString());const d=await r.json();if(d.error)throw new Error(d.error);allEntries=d.entries||[];renderBreadcrumb();renderEntries()}catch(e){toast('加载失败: '+e.message,'error')}
}
function renderBreadcrumb(){
  const b=document.getElementById('breadcrumb');
  if(!currentDir){b.innerHTML='<span class="current">根目录</span>';return}
  const parts=currentDir.split('/');let h='<a data-dir="">根目录</a>',p='';
  parts.forEach((part,i)=>{p+=(p?'/':'')+part;if(i===parts.length-1)h+=' <span>/</span> <span class="current">'+part+'</span>';else h+=' <span>/</span> <a data-dir="'+p+'">'+part+'</a>'});
  b.innerHTML=h;
}
function renderEntries(){
  const q=document.getElementById('searchBox').value.toLowerCase();
  let filtered=allEntries.filter(e=>q?e.name.toLowerCase().includes(q):true);
  filtered.sort((a,b)=>{if(a.type!==b.type)return a.type==='dir'?-1:1;return a.name.localeCompare(b.name)});
  const el=document.getElementById('fileList');
  if(filtered.length===0){el.innerHTML='<div class="empty-state">'+(q?'无匹配':'目录为空')+'</div>';return}
  el.innerHTML=filtered.map(e=>{
    if(e.type==='dir')return '<div class="file-item dir" data-dir="'+(currentDir?currentDir+'/':'')+e.name+'"><div class="file-icon" style="color:var(--warning)">📁</div><div class="file-info"><div class="file-name">'+e.name+'/</div></div></div>';
    const isText=e.metadata?.isText!==false,isImg=e.metadata?.isImage===true,hasPwd=e.metadata?.hasPassword===true;
    const size=e.metadata?.size||0,sizeClass=size<102400?'size-sm':size<1048576?'size-md':'size-lg';
    const ext=e.name.includes('.')?e.name.split('.').pop().toUpperCase():'?';
    return '<div class="file-item"><div class="file-icon">'+(isImg?'🖼':ext.substring(0,3))+'</div><div class="file-info"><div class="file-name"><a data-action="preview" data-key="'+e.key+'" data-img="'+isImg+'" data-text="'+isText+'">'+e.name+'</a>'+(hasPwd?' <span class="lock-icon">🔒</span>':'')+'</div><div class="file-meta"><span class="'+sizeClass+'">'+formatSize(e.metadata?.size)+'</span><span>'+ (e.metadata?.contentType||'')+'</span></div></div><div class="file-actions">'+(isText?'<button class="btn btn-sm" data-action="edit" data-key="'+e.key+'">编辑</button>':'')+'<button class="btn btn-sm" data-action="download" data-key="'+e.key+'" data-pwd="'+hasPwd+'">下载</button><button class="btn btn-sm btn-danger" data-action="delete" data-key="'+e.key+'">删除</button></div></div>';
  }).join('');
}
// 事件委托：统一在 fileList 容器上处理所有点击
document.getElementById('fileList').addEventListener('click',e=>{
  const dirEl=e.target.closest('.file-item.dir');
  if(dirEl){currentDir=dirEl.dataset.dir;loadEntries();return}
  const btn=e.target.closest('[data-action]');
  if(!btn)return;
  const action=btn.dataset.action,key=btn.dataset.key;
  if(action==='preview'){e.preventDefault();if(btn.dataset.img==='true')previewImage(key);else if(btn.dataset.text==='true')openEditor(key)}
  else if(action==='edit')openEditor(key);
  else if(action==='download')downloadFile(key,btn.dataset.pwd==='true');
  else if(action==='delete')deleteFile(key);
});
// 面包屑事件委托
document.getElementById('breadcrumb').addEventListener('click',e=>{
  const a=e.target.closest('a[data-dir]');
  if(a){currentDir=a.dataset.dir;loadEntries()}
});
function navigateTo(d){currentDir=d;loadEntries()}

// ========== 上传 ==========
document.getElementById('uploadBtn').addEventListener('click',()=>{document.getElementById('uploadDir').value=currentDir;document.getElementById('uploadPassword').value='';document.getElementById('uploadFileNames').textContent='未选择文件';document.getElementById('uploadProgressWrap').classList.add('hidden');pendingFiles=null;document.getElementById('uploadDialog').classList.remove('hidden');const inp=document.getElementById('uploadDialog').querySelector('input[type=file]')||(()=>{const i=document.createElement('input');i.type='file';i.multiple=true;i.className='hidden';i.addEventListener('change',()=>{if(i.files.length>0){pendingFiles=i.files;document.getElementById('uploadFileNames').textContent=Array.from(i.files).map(f=>f.name).join(', ')}});document.getElementById('uploadDialog').appendChild(i);return i})();inp.click()});
document.getElementById('uploadDialogClose').addEventListener('click',()=>document.getElementById('uploadDialog').classList.add('hidden'));
document.getElementById('uploadDialogCancel').addEventListener('click',()=>document.getElementById('uploadDialog').classList.add('hidden'));
document.getElementById('uploadDialogConfirm').addEventListener('click',async()=>{
  if(!pendingFiles||pendingFiles.length===0){toast('请选择文件','error');return}
  const dir=document.getElementById('uploadDir').value.trim(),password=document.getElementById('uploadPassword').value;
  const progressWrap=document.getElementById('uploadProgressWrap'),progressBar=document.getElementById('uploadProgressBar'),progressText=document.getElementById('uploadProgressText');
  progressWrap.classList.remove('hidden');
  let done=0,total=pendingFiles.length, totalBytes=0, uploadedBytes=0;
  for(const f of pendingFiles) totalBytes+=f.size;

  for(const f of pendingFiles){
    try{
      const fd=new FormData();fd.append('file',f);if(dir)fd.append('dir',dir);if(password)fd.append('password',password);
      await new Promise((resolve,reject)=>{
        const xhr=new XMLHttpRequest();
        xhr.open('POST','/api/upload');
        xhr.upload.onprogress=(e)=>{if(e.lengthComputable){const fileDone=uploadedBytes+e.loaded;const pct=Math.round(fileDone/totalBytes*100);progressBar.style.width=pct+'%';progressText.textContent=f.name+' ('+Math.round(e.loaded/e.total*100)+'%)'}};
        xhr.onload=()=>{try{const d=JSON.parse(xhr.responseText);if(d.error)reject(new Error(d.error));else{uploadedBytes+=f.size;done++;progressBar.style.width=Math.round(uploadedBytes/totalBytes*100)+'%';progressText.textContent='已完成 '+done+'/'+total;resolve()}}catch(e){reject(e)}};
        xhr.onerror=()=>reject(new Error('网络错误'));
        xhr.send(fd);
      });
    }catch(e){toast('上传失败: '+e.message,'error');progressWrap.classList.add('hidden');return}
  }
  toast('全部上传成功 ('+done+' 个文件)','success');
  document.getElementById('uploadDialog').classList.add('hidden');pendingFiles=null;progressWrap.classList.add('hidden');
  // KV 最终一致性，延迟后刷新，如果没出来再重试一次
  setTimeout(async()=>{await loadEntries();setTimeout(loadEntries,2000)},1500);
});

// ========== 下载 ==========
async function downloadFile(key,needsPwd){
  if(needsPwd){const pwd=await promptPassword();if(!pwd)return;dl(key,pwd)}else dl(key)
}
async function dl(key,pwd){const e=allEntries.find(e=>e.key===key);const name=e?.name||key;const a=document.createElement('a');a.href=API+'/'+encodeURIComponent(key)+'/download'+(pwd?'?password='+encodeURIComponent(pwd):'');a.download=name;a.click()}
function promptPassword(){return new Promise(resolve=>{document.getElementById('pwdInput').value='';document.getElementById('pwdDialog').classList.remove('hidden');document.getElementById('pwdInput').focus();pwdResolve=resolve})}
document.getElementById('pwdConfirm').addEventListener('click',()=>{document.getElementById('pwdDialog').classList.add('hidden');if(pwdResolve)pwdResolve(document.getElementById('pwdInput').value);pwdResolve=null});
document.getElementById('pwdCancel').addEventListener('click',()=>{document.getElementById('pwdDialog').classList.add('hidden');if(pwdResolve)pwdResolve(null);pwdResolve=null});

// ========== 删除 ==========
async function deleteFile(key){const e=allEntries.find(e=>e.key===key);if(!confirm('删除 "'+(e?.name||key)+'"？'))return;try{const r=await fetch(API+'/'+encodeURIComponent(key),{method:'DELETE'});const d=await r.json();if(d.error)throw new Error(d.error);toast('已删除','success');loadEntries()}catch(e){toast('删除失败: '+e.message,'error')}}

// ========== 图片预览 ==========
function previewImage(key){document.getElementById('imgPreviewImg').src=API+'/'+encodeURIComponent(key)+'/download';document.getElementById('imgPreview').classList.remove('hidden')}
document.getElementById('imgPreviewClose').addEventListener('click',()=>document.getElementById('imgPreview').classList.add('hidden'));
document.getElementById('imgPreview').addEventListener('click',e=>{if(e.target===document.getElementById('imgPreview'))document.getElementById('imgPreview').classList.add('hidden')});

// ========== 编辑 ==========
async function openEditor(key){const e=allEntries.find(e=>e.key===key);if(!e)return;editingKey=key;document.getElementById('editModalTitle').textContent='编辑: '+e.name;const ta=document.getElementById('editTextarea');ta.value='加载中...';ta.disabled=true;document.getElementById('editModal').classList.remove('hidden');try{const r=await fetch(API+'/'+encodeURIComponent(key));const d=await r.json();ta.value=d.content||''}catch(e){toast('加载失败','error')}ta.disabled=false;ta.focus()}
function closeEditor(){document.getElementById('editModal').classList.add('hidden');editingKey=null;document.getElementById('editTextarea').value=''}
document.getElementById('editModalClose').addEventListener('click',closeEditor);
document.getElementById('editModalCancel').addEventListener('click',closeEditor);
document.getElementById('editModal').addEventListener('click',e=>{if(e.target===document.getElementById('editModal'))closeEditor()});
document.getElementById('editModalSave').addEventListener('click',async()=>{if(!editingKey)return;try{const r=await fetch(API+'/'+encodeURIComponent(editingKey),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:document.getElementById('editTextarea').value})});const d=await r.json();if(d.error)throw new Error(d.error);toast('已保存','success');closeEditor();loadEntries()}catch(e){toast('保存失败: '+e.message,'error')}});
document.getElementById('editTextarea').addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key==='s'){e.preventDefault();document.getElementById('editModalSave').click()}});

// ========== 新建目录 ==========
document.getElementById('mkdirBtn').addEventListener('click',()=>{const n=prompt('目录名：');if(!n||!n.trim())return;const p=currentDir?currentDir+'/'+n.trim():n.trim();fetch('/api/mkdir',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({dir:p})}).then(r=>r.json()).then(d=>{if(d.error)throw new Error(d.error);toast('已创建: '+n,'success');loadEntries()}).catch(e=>toast('创建失败: '+e.message,'error'))});

// ========== 搜索/刷新 ==========
document.getElementById('searchBox').addEventListener('input',renderEntries);
document.getElementById('refreshBtn').addEventListener('click',loadEntries);

// ========== 云函数 ==========
async function loadScripts(){try{const r=await fetch('/api/scripts');const d=await r.json();if(d.error)throw new Error(d.error);const el=document.getElementById('scriptList');if(!d.scripts||d.scripts.length===0){el.innerHTML='<div class="empty-state">暂无脚本</div>';return}el.innerHTML=d.scripts.map(s=>'<div class="script-card"><div style="display:flex;align-items:center;justify-content:space-between"><h4 style="cursor:pointer" data-action="editScript" data-id="'+s.id+'">'+s.name+'</h4><button class="btn btn-accent btn-sm" data-action="runScript" data-id="'+s.id+'">▶ 运行</button></div><p>'+new Date(s.updatedAt).toLocaleString()+'</p><div class="run-output hidden" id="scriptOut_'+s.id+'"></div></div>').join('')}catch(e){toast('加载失败','error')}}
// 脚本列表事件委托：编辑/运行
document.getElementById('scriptList').addEventListener('click',async(e)=>{
  const btn=e.target.closest('[data-action]');if(!btn)return;
  const id=btn.dataset.id;
  if(btn.dataset.action==='editScript'){openScript(id)}
  else if(btn.dataset.action==='runScript'){
    const out=document.getElementById('scriptOut_'+id);out.textContent='执行中...';out.className='run-output';out.classList.remove('hidden');
    try{const r=await fetch('/api/scripts/'+id+'/run',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});const d=await r.json();
    if(d.error){out.textContent='错误: '+d.error;out.className='run-output error'}
    else {let txt='';if(d.output&&d.output.length>0)txt+=d.output.join('\\n')+'\\n';if(d.result!==undefined&&d.result!==null)txt+='=> '+JSON.stringify(d.result);out.textContent=txt||'(无输出)';out.className='run-output success'}
    }catch(e){out.textContent='执行异常: '+e.message;out.className='run-output error'}
  }
});
async function openScript(id){
  try{const r=await fetch('/api/scripts/'+id);const d=await r.json();if(d.error)throw new Error(d.error);
  document.getElementById('scriptName').value=d.name||'';document.getElementById('scriptCode').value=d.code||'';
  document.getElementById('scriptModalTitle').textContent=d.name||'新建脚本';
  const modal=document.getElementById('scriptModal');
  modal.dataset.id=id||'';delete modal.dataset.adminUid;delete modal.dataset.adminSid;
  document.getElementById('scriptParams').value='';
  document.getElementById('runOutput').classList.add('hidden');
  modal.classList.remove('hidden');
  }catch(e){toast('加载失败','error')}
}
document.getElementById('newScriptBtn').addEventListener('click',()=>{const m=document.getElementById('scriptModal');document.getElementById('scriptName').value='';document.getElementById('scriptCode').value='';document.getElementById('scriptParams').value='';document.getElementById('scriptModalTitle').textContent='新建脚本';m.dataset.id='';delete m.dataset.adminUid;delete m.dataset.adminSid;document.getElementById('runOutput').classList.add('hidden');m.classList.remove('hidden')});
document.getElementById('scriptModalClose').addEventListener('click',()=>{const m=document.getElementById('scriptModal');m.classList.add('hidden');delete m.dataset.adminUid;delete m.dataset.adminSid});
document.getElementById('scriptModalCancel').addEventListener('click',()=>{const m=document.getElementById('scriptModal');m.classList.add('hidden');delete m.dataset.adminUid;delete m.dataset.adminSid});
document.getElementById('scriptSave').addEventListener('click',async()=>{
  const name=document.getElementById('scriptName').value.trim(),code=document.getElementById('scriptCode').value;
  if(!name){toast('请输入名称','error');return}
  const modal=document.getElementById('scriptModal');
  const id=modal.dataset.id,adminUid=modal.dataset.adminUid,adminSid=modal.dataset.adminSid;
  try{
    let url;const method='POST';
    if(adminUid&&adminSid)url='/api/admin/scripts/'+adminUid+'/'+adminSid;
    else url='/api/scripts'+(id?'/'+id:'');
    const r=await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify({name,code})});const d=await r.json();if(d.error)throw new Error(d.error);
    toast('已保存','success');modal.classList.add('hidden');
    if(adminUid)loadAdminData();else loadScripts();
  }catch(e){toast('保存失败: '+e.message,'error')}
});
document.getElementById('scriptRun').addEventListener('click',async()=>{
  const code=document.getElementById('scriptCode').value;if(!code.trim()){toast('请输入代码','error');return}
  const out=document.getElementById('runOutput');out.textContent='执行中...';out.className='run-output';out.classList.remove('hidden');
  // 解析参数 JSON
  let params=null;
  const paramsStr=document.getElementById('scriptParams').value.trim();
  if(paramsStr){try{params=JSON.parse(paramsStr)}catch(e){toast('参数 JSON 格式错误: '+e.message,'error');return}}
  const body={code};if(params)body.params=params;
  try{const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const d=await r.json();
  if(d.error){out.textContent='错误: '+d.error;out.className='run-output error'}
  else {let txt='';if(d.output&&d.output.length>0)txt+=d.output.join('\\n')+'\\n';if(d.result!==undefined&&d.result!==null)txt+='=> '+JSON.stringify(d.result);out.textContent=txt||'(无输出)';out.className='run-output success'}
  }catch(e){out.textContent='执行异常: '+e.message;out.className='run-output error'}
});
document.getElementById('refreshScriptsBtn').addEventListener('click',loadScripts);

// ========== API Key 管理 ==========
async function loadApiKeys(){
  try{const r=await fetch('/api/apikeys');const d=await r.json();if(d.error)throw new Error(d.error);
  const el=document.getElementById('apiKeyList');
  if(!d.keys||d.keys.length===0){el.innerHTML='<div class="empty-state">暂无 API Key，点击上方按钮创建</div>';return}
  el.innerHTML=d.keys.map(k=>'<div class="file-item"><div class="file-icon" style="color:var(--accent)">🔑</div><div class="file-info"><div class="file-name">'+k.name+'</div><div class="file-meta"><span>'+k.permissions.join(', ')+'</span><span>'+new Date(k.createdAt).toLocaleString()+'</span></div></div><div class="file-actions"><button class="btn btn-sm btn-danger" data-action="deleteApiKey" data-id="'+k.id+'">删除</button></div></div>').join('');
  el.querySelectorAll('[data-action="deleteApiKey"]').forEach(b=>b.addEventListener('click',async()=>{if(!confirm('删除此 API Key？'))return;try{const r=await fetch('/api/apikeys/'+b.dataset.id,{method:'DELETE'});const d=await r.json();if(d.error)throw new Error(d.error);toast('已删除','success');loadApiKeys()}catch(e){toast('删除失败: '+e.message,'error')}}))
  }catch(e){toast('加载失败','error')}
}
document.getElementById('createApiKeyBtn').addEventListener('click',()=>{document.getElementById('apiKeyName').value='';document.getElementById('apiKeyResult').classList.add('hidden');document.getElementById('apiKeyModal').querySelectorAll('input[type=checkbox]').forEach(c=>c.checked=false);document.getElementById('apiKeyModal').classList.remove('hidden')});
document.getElementById('apiKeyModalClose').addEventListener('click',()=>document.getElementById('apiKeyModal').classList.add('hidden'));
document.getElementById('apiKeyModalCancel').addEventListener('click',()=>document.getElementById('apiKeyModal').classList.add('hidden'));
document.getElementById('apiKeyCreate').addEventListener('click',async()=>{
  const name=document.getElementById('apiKeyName').value.trim();
  if(!name){toast('请输入名称','error');return}
  const perms=Array.from(document.getElementById('apiKeyModal').querySelectorAll('input[type=checkbox]:checked')).map(c=>c.value);
  if(perms.length===0){toast('请至少选择一个权限','error');return}
  try{const r=await fetch('/api/apikeys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,permissions:perms})});const d=await r.json();
  if(d.error)throw new Error(d.error);
  document.getElementById('apiKeyValue').textContent=d.key;document.getElementById('apiKeyResult').classList.remove('hidden');
  toast('API Key 已创建','success');loadApiKeys()}catch(e){toast('创建失败: '+e.message,'error')}
});
document.getElementById('refreshApiKeysBtn').addEventListener('click',loadApiKeys);

// ========== Admin 管理 ==========
let adminTab='users',adminData=[];
document.getElementById('adminTabUsers').addEventListener('click',()=>{adminTab='users';loadAdminData()});
document.getElementById('adminTabFiles').addEventListener('click',()=>{adminTab='files';loadAdminData()});
document.getElementById('adminTabScripts').addEventListener('click',()=>{adminTab='scripts';loadAdminData()});
document.getElementById('adminRefreshBtn').addEventListener('click',loadAdminData);
document.getElementById('adminSearchBox').addEventListener('input',renderAdminList);

async function loadAdminData(){
  const btns=[document.getElementById('adminTabUsers'),document.getElementById('adminTabFiles'),document.getElementById('adminTabScripts')];
  btns.forEach(b=>b.classList.remove('btn-accent'));
  if(adminTab==='users'){btns[0].classList.add('btn-accent');try{const r=await fetch('/api/admin/users');const d=await r.json();if(d.error)throw new Error(d.error);adminData=d.users||[]}catch(e){toast('加载失败','error');return}}
  else if(adminTab==='files'){btns[1].classList.add('btn-accent');try{const r=await fetch('/api/admin/files');const d=await r.json();if(d.error)throw new Error(d.error);adminData=d.files||[]}catch(e){toast('加载失败','error');return}}
  else if(adminTab==='scripts'){btns[2].classList.add('btn-accent');try{const r=await fetch('/api/admin/scripts');const d=await r.json();if(d.error)throw new Error(d.error);adminData=d.scripts||[]}catch(e){toast('加载失败','error');return}}
  renderAdminList();
}
function renderAdminList(){
  const q=document.getElementById('adminSearchBox').value.toLowerCase();
  let filtered=adminData.filter(e=>q?JSON.stringify(e).toLowerCase().includes(q):true);
  const el=document.getElementById('adminList');
  if(filtered.length===0){el.innerHTML='<div class="empty-state">'+(q?'无匹配':'暂无数据')+'</div>';return}
  if(adminTab==='users'){
    el.innerHTML=filtered.map(u=>'<div class="file-item"><div class="file-icon" style="color:'+(u.isAdmin?'var(--danger)':'var(--accent)')+'">'+(u.isAdmin?'👑':'👤')+'</div><div class="file-info"><div class="file-name">'+u.username+' '+(u.isAdmin?'<span style="color:var(--danger);font-size:0.7rem">管理员</span>':'')+'</div><div class="file-meta"><span>ID: '+u.userId+'</span><span>'+new Date(u.createdAt).toLocaleString()+'</span></div></div><div class="file-actions"><button class="btn btn-sm" data-action="adminFiles" data-uid="'+u.userId+'">查看文件</button></div></div>').join('');
    el.querySelectorAll('[data-action="adminFiles"]').forEach(b=>b.addEventListener('click',async()=>{try{const r=await fetch('/api/admin/files?userId='+b.dataset.uid);const d=await r.json();if(d.error)throw new Error(d.error);adminData=d.files||[];adminTab='files';document.getElementById('adminTabFiles').click();renderAdminList()}catch(e){toast('加载失败','error')}}));
  }else if(adminTab==='files'){
    el.innerHTML=filtered.map(f=>'<div class="file-item"><div class="file-icon">📄</div><div class="file-info"><div class="file-name">'+f.name+'</div><div class="file-meta"><span class="'+(f.size<102400?'size-sm':f.size<1048576?'size-md':'size-lg')+'">'+formatSize(f.size)+'</span><span>用户: '+f.userId+'</span><span>'+new Date(f.uploadedAt).toLocaleString()+'</span></div></div><div class="file-actions">'+(f.isText?'<button class="btn btn-sm" data-action="adminEditFile" data-key="'+encodeURIComponent(f.key)+'">编辑</button>':'')+'<button class="btn btn-sm" data-action="adminDownloadFile" data-key="'+encodeURIComponent(f.key)+'" data-pwd="'+f.hasPassword+'">下载</button><button class="btn btn-sm btn-danger" data-action="adminDelFile" data-key="'+encodeURIComponent(f.key)+'">删除</button></div></div>').join('');
    el.querySelectorAll('[data-action="adminEditFile"]').forEach(b=>b.addEventListener('click',()=>{openEditor(decodeURIComponent(b.dataset.key))}));
    el.querySelectorAll('[data-action="adminDownloadFile"]').forEach(b=>b.addEventListener('click',()=>{adminDownloadFile(decodeURIComponent(b.dataset.key),b.dataset.pwd==='true')}));
    el.querySelectorAll('[data-action="adminDelFile"]').forEach(b=>b.addEventListener('click',async()=>{if(!confirm('删除此文件？'))return;try{const r=await fetch('/api/admin/files/'+b.dataset.key,{method:'DELETE'});const d=await r.json();if(d.error)throw new Error(d.error);toast('已删除','success');loadAdminData()}catch(e){toast('删除失败: '+e.message,'error')}}));
  }else if(adminTab==='scripts'){
    el.innerHTML=filtered.map(s=>'<div class="file-item"><div class="file-icon" style="color:var(--warning)">⚡</div><div class="file-info"><div class="file-name">'+s.name+'</div><div class="file-meta"><span>用户: '+s.userId+'</span><span>'+new Date(s.updatedAt).toLocaleString()+'</span></div></div><div class="file-actions"><button class="btn btn-sm" data-action="adminEditScript" data-uid="'+s.userId+'" data-sid="'+s.id+'">编辑</button><button class="btn btn-sm btn-danger" data-action="adminDelScript" data-uid="'+s.userId+'" data-sid="'+s.id+'">删除</button></div></div>').join('');
    el.querySelectorAll('[data-action="adminEditScript"]').forEach(b=>b.addEventListener('click',()=>{adminOpenScript(b.dataset.uid,b.dataset.sid)}));
    el.querySelectorAll('[data-action="adminDelScript"]').forEach(b=>b.addEventListener('click',async()=>{if(!confirm('删除此脚本？'))return;try{const r=await fetch('/api/admin/scripts/'+b.dataset.uid+'/'+b.dataset.sid,{method:'DELETE'});const d=await r.json();if(d.error)throw new Error(d.error);toast('已删除','success');loadAdminData()}catch(e){toast('删除失败: '+e.message,'error')}}));
  }
}

// ========== Admin 辅助函数 ==========
/** 管理员下载文件 */
async function adminDownloadFile(key,needsPwd){
  if(needsPwd){const pwd=await promptPassword();if(!pwd)return;adminDl(key,pwd)}else adminDl(key)
}
async function adminDl(key,pwd){
  const a=document.createElement('a');
  a.href=API+'/'+encodeURIComponent(key)+'/download'+(pwd?'?password='+encodeURIComponent(pwd):'');
  a.download=key.split('/').pop()||key;
  a.click()
}
/** 管理员打开脚本编辑器 */
async function adminOpenScript(userId,scriptId){
  try{
    const r=await fetch('/api/admin/scripts/'+userId+'/'+scriptId);
    const d=await r.json();
    if(d.error)throw new Error(d.error);
    document.getElementById('scriptName').value=d.name||'';
    document.getElementById('scriptCode').value=d.code||'';
    document.getElementById('scriptParams').value='';
    document.getElementById('scriptModalTitle').textContent='[管理] '+d.name;
    const modal=document.getElementById('scriptModal');
    modal.dataset.id='';modal.dataset.adminUid=userId;modal.dataset.adminSid=scriptId;
    document.getElementById('runOutput').classList.add('hidden');
    modal.classList.remove('hidden');
  }catch(e){toast('加载失败: '+e.message,'error')}
}

// ========== 初始化 ==========
const params=new URLSearchParams(location.search);currentDir=params.get('dir')||'';loadEntries();
</script>
</body>
</html>`;

const HTML_UPLOAD = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>文件上传</title>
<style>
  :root { --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3; --text-dim:#8b949e; --accent:#58a6ff; --success:#3fb950; --danger:#f85149; --radius:8px; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; display:flex; align-items:center; justify-content:center; }
  .card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:28px; width:100%; max-width:480px; }
  .card h1 { text-align:center; font-size:1.3rem; margin-bottom:16px; }
  .field { margin-bottom:12px; }
  .field label { display:block; font-size:0.8rem; color:var(--text-dim); margin-bottom:4px; }
  .field input { width:100%; padding:8px 12px; border-radius:6px; border:1px solid var(--border); background:var(--bg); color:var(--text); font-size:0.9rem; outline:none; }
  .field input:focus { border-color:var(--accent); }
  .dropzone { border:2px dashed var(--border); border-radius:var(--radius); padding:32px 16px; text-align:center; cursor:pointer; transition:border-color .2s; margin-bottom:12px; }
  .dropzone:hover, .dropzone.dragover { border-color:var(--accent); }
  .dropzone p { color:var(--text-dim); font-size:0.85rem; }
  .dropzone strong { color:var(--accent); }
  .file-list { font-size:0.82rem; color:var(--success); margin-bottom:12px; max-height:120px; overflow:auto; }
  .btn { width:100%; padding:10px; border-radius:var(--radius); border:none; background:var(--accent); color:#fff; cursor:pointer; font-size:0.9rem; margin-top:6px; }
  .btn:hover { opacity:0.9; }
  .btn:disabled { opacity:0.5; cursor:not-allowed; }
  .status { text-align:center; margin-top:10px; font-size:0.82rem; }
  .status.success { color:var(--success); }
  .status.error { color:var(--danger); }
  .progress { height:4px; background:var(--border); border-radius:2px; margin-top:8px; overflow:hidden; }
  .progress-bar { height:100%; background:var(--accent); transition:width .3s; }
  .hidden { display:none !important; }
</style>
</head>
<body>
<div class="card">
  <h1>文件上传</h1>
  <div class="field">
    <label>API Key</label>
    <input type="text" id="apiKey" placeholder="输入你的 API Key">
  </div>
  <div class="field">
    <label>目标目录（可选）</label>
    <input type="text" id="dir" placeholder="留空=根目录">
  </div>
  <div class="dropzone" id="dropzone">
    <p>拖拽文件到此处，或 <strong>点击选择文件</strong></p>
    <input type="file" id="fileInput" class="hidden" multiple>
  </div>
  <div class="file-list hidden" id="fileList"></div>
  <button class="btn" id="uploadBtn" disabled>上传</button>
  <div class="progress hidden" id="progress"><div class="progress-bar" id="progressBar" style="width:0%"></div></div>
  <div class="status hidden" id="status"></div>
</div>
<script>
const dropzone=document.getElementById('dropzone'),fileInput=document.getElementById('fileInput');
const fileList=document.getElementById('fileList'),uploadBtn=document.getElementById('uploadBtn');
const status=document.getElementById('status'),progress=document.getElementById('progress'),progressBar=document.getElementById('progressBar');
let pendingFiles=null;

dropzone.addEventListener('click',()=>fileInput.click());
dropzone.addEventListener('dragover',e=>{e.preventDefault();dropzone.classList.add('dragover')});
dropzone.addEventListener('dragleave',()=>dropzone.classList.remove('dragover'));
dropzone.addEventListener('drop',e=>{e.preventDefault();dropzone.classList.remove('dragover');setFiles(e.dataTransfer.files)});
fileInput.addEventListener('change',()=>setFiles(fileInput.files));

function setFiles(files){
  if(!files||files.length===0)return;
  pendingFiles=files;
  fileList.innerHTML=Array.from(files).map(f=>'<div>'+f.name+' ('+(f.size<1024?f.size+' B':f.size<1048576?(f.size/1024).toFixed(1)+' KB':(f.size/1048576).toFixed(1)+' MB')+')</div>').join('');
  fileList.classList.remove('hidden');uploadBtn.disabled=false;
}

uploadBtn.addEventListener('click',async()=>{
  const apiKey=document.getElementById('apiKey').value.trim();
  const dir=document.getElementById('dir').value.trim();
  if(!apiKey){showStatus('请输入 API Key','error');return}
  if(!pendingFiles||pendingFiles.length===0){showStatus('请选择文件','error');return}
  uploadBtn.disabled=true;progress.classList.remove('hidden');
  let done=0;
  for(const file of pendingFiles){
    try{
      const fd=new FormData();fd.append('file',file);if(dir)fd.append('dir',dir);
      const r=await fetch('/api/upload',{method:'POST',headers:{'Authorization':'Bearer '+apiKey},body:fd});
      const d=await r.json();
      if(d.error)throw new Error(d.error);
      done++;progressBar.style.width=(done/pendingFiles.length*100)+'%';
    }catch(e){showStatus(file.name+': '+e.message,'error');uploadBtn.disabled=false;return}
  }
  showStatus('全部上传成功 ('+done+' 个文件)','success');pendingFiles=null;fileList.classList.add('hidden');uploadBtn.disabled=true;progress.classList.add('hidden');progressBar.style.width='0%';
});

function showStatus(msg,type){status.textContent=msg;status.className='status '+type;status.classList.remove('hidden')}
</script>
</body>
</html>`;

// ==================== Worker 入口 ====================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' } });
    }

    const cors = { 'Access-Control-Allow-Origin': '*' };

    try {
      // ====== 认证路由 ======
      if (method === 'POST' && pathname === '/api/auth/register') return handleRegister(request, env, cors);
      if (method === 'POST' && pathname === '/api/auth/login') return handleLogin(request, env, cors);
      if (method === 'POST' && pathname === '/api/auth/logout') return handleLogout(cors);

      // ====== 首次安装 ======
      if (method === 'POST' && pathname === '/api/admin/setup') return handleAdminSetup(request, env, cors);

      // ====== 独立上传页面（无需登录，通过 API Key 访问） ======
      if (method === 'GET' && pathname === '/upload') {
        return new Response(HTML_UPLOAD, { headers: { 'Content-Type': 'text/html;charset=utf-8', ...cors } });
      }

      // ====== 检查是否首次使用（无用户 → 显示安装页） ======
      const user = await auth(request, env);
      if (!user) {
        const userList = await env.FILE_STORE.list({ prefix: 'user:', limit: 1 });
        if (userList.keys.length === 0 && pathname === '/') {
          return new Response(HTML_SETUP, { headers: { 'Content-Type': 'text/html;charset=utf-8', ...cors } });
        }
        if (pathname === '/') {
          return new Response(HTML_LOGIN, { headers: { 'Content-Type': 'text/html;charset=utf-8', ...cors } });
        }
        if (pathname.startsWith('/api/')) return json({ error: '请先登录' }, 401, cors);
        return new Response(HTML_LOGIN, { headers: { 'Content-Type': 'text/html;charset=utf-8', ...cors } });
      }

      // ====== 已登录 → 主页面 ======
      if (method === 'GET' && pathname === '/') {
        let html = HTML_APP.replace('id="userDisplay">', 'id="userDisplay">' + user.username);
        if (user.isAdmin) html = html.replace('<!-- ADMIN_NAV -->', '<a data-page="admin" style="color:var(--danger)">管理</a>');
        return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8', ...cors } });
      }

      // ====== Admin API ======
      if (user.isAdmin) {
        if (method === 'GET' && pathname === '/api/admin/users') return handleAdminUsers(env, cors);
        if (method === 'GET' && pathname === '/api/admin/files') {
          const uidFilter = url.searchParams.get('userId') || '';
          return handleAdminFiles(uidFilter, env, cors);
        }
        if (method === 'DELETE' && pathname.startsWith('/api/admin/files/')) {
          return handleAdminDeleteFile(decodeURIComponent(pathname.substring('/api/admin/files/'.length)), env, cors);
        }
        if (method === 'GET' && pathname === '/api/admin/scripts') return handleAdminScripts(env, cors);
        const admScriptMatch = pathname.match(/^\/api\/admin\/scripts\/(.+)\/(.+)$/);
        if (admScriptMatch && method === 'DELETE') {
          return handleAdminDeleteScript(admScriptMatch[1], admScriptMatch[2], env, cors);
        }
        if (admScriptMatch && method === 'GET') {
          return handleAdminGetScript(admScriptMatch[1], admScriptMatch[2], env, cors);
        }
        if (admScriptMatch && method === 'POST') {
          return handleAdminSaveScript(admScriptMatch[1], admScriptMatch[2], request, env, cors);
        }
      }

      // ====== API Key 管理 ======
      if (method === 'GET' && pathname === '/api/apikeys') {
        return handleListApiKeys(user.userId, env, cors);
      }
      if (method === 'POST' && pathname === '/api/apikeys') {
        return handleCreateApiKey(user.userId, user.username, request, env, cors);
      }
      const akMatch = pathname.match(/^\/api\/apikeys\/(.+)$/);
      if (akMatch && method === 'DELETE') {
        return handleDeleteApiKey(user.userId, akMatch[1], env, cors);
      }

      // ====== 文件 API ======
      if (method === 'GET' && pathname === '/api/files' && (url.searchParams.has('dir') || !url.searchParams.has('dir'))) {
        if (!checkPerm(user, 'files:read')) return json({ error: '无此权限' }, 403, cors);
        return handleListDir(user.userId, url.searchParams.get('dir') || '', env, cors);
      }
      if (method === 'POST' && pathname === '/api/upload') {
        if (!checkPerm(user, 'files:write')) return json({ error: '无此权限' }, 403, cors);
        return handleUpload(user.userId, request, env, cors);
      }
      if (method === 'POST' && pathname === '/api/mkdir') {
        if (!checkPerm(user, 'files:write')) return json({ error: '无此权限' }, 403, cors);
        return handleMkdir(user.userId, request, env, cors);
      }

      const route = parseRoute(pathname);
      if (route) {
        if (!route.key.startsWith(user.userId + '/') && !user.isAdmin) return json({ error: '无权访问' }, 403, cors);
        if (route.type === 'download' && method === 'GET') {
          if (!checkPerm(user, 'files:read')) return json({ error: '无此权限' }, 403, cors);
          return handleDownload(route.key, url.searchParams.get('password'), env, cors);
        }
        if (route.type === 'file' && method === 'GET') {
          if (!checkPerm(user, 'files:read')) return json({ error: '无此权限' }, 403, cors);
          return handleGetFile(route.key, env, cors);
        }
        if (route.type === 'file' && method === 'PUT') {
          if (!checkPerm(user, 'files:edit')) return json({ error: '无此权限' }, 403, cors);
          return handleUpdate(route.key, request, env, cors);
        }
        if (route.type === 'file' && method === 'DELETE') {
          if (!checkPerm(user, 'files:delete')) return json({ error: '无此权限' }, 403, cors);
          return handleDelete(route.key, env, cors);
        }
      }

      // ====== 云函数 API ======
      if (method === 'GET' && pathname === '/api/scripts') {
        if (!checkPerm(user, 'scripts:read')) return json({ error: '无此权限' }, 403, cors);
        return handleListScripts(user.userId, env, cors);
      }
      if (method === 'POST' && pathname === '/api/scripts') {
        if (!checkPerm(user, 'scripts:write')) return json({ error: '无此权限' }, 403, cors);
        return handleSaveScript(user.userId, null, request, env, cors);
      }
      const scriptMatch = pathname.match(/^\/api\/scripts\/(.+)$/);
      if (scriptMatch && method === 'GET') {
        if (!checkPerm(user, 'scripts:read')) return json({ error: '无此权限' }, 403, cors);
        return handleGetScript(user.userId, scriptMatch[1], env, cors);
      }
      if (scriptMatch && method === 'POST') {
        if (!checkPerm(user, 'scripts:write')) return json({ error: '无此权限' }, 403, cors);
        return handleSaveScript(user.userId, scriptMatch[1], request, env, cors);
      }
      // 执行已保存的脚本
      const scriptRunMatch = pathname.match(/^\/api\/scripts\/(.+)\/run$/);
      if (scriptRunMatch && method === 'POST') {
        if (!checkPerm(user, 'scripts:execute')) return json({ error: '无此权限' }, 403, cors);
        return handleRunScript(user.userId, scriptRunMatch[1], request, env, cors);
      }
      if (method === 'POST' && pathname === '/api/run') {
        if (!checkPerm(user, 'scripts:execute')) return json({ error: '无此权限' }, 403, cors);
        return handleRun(user.userId, request, env, cors);
      }

      return json({ error: 'Not Found' }, 404, cors);
    } catch (e) {
      return json({ error: e.message }, 500, cors);
    }
  },
};

// ==================== 认证处理 ====================

async function handleRegister(request, env, cors) {
  let body; try { body = await request.json(); } catch { return json({ error: '无效请求' }, 400, cors); }
  const { username, password } = body;
  if (!username || !password) return json({ error: '缺少用户名或密码' }, 400, cors);
  if (!/^[a-zA-Z0-9]{3,20}$/.test(username)) return json({ error: '用户名需3-20位字母数字' }, 400, cors);
  if (password.length < 6) return json({ error: '密码至少6位' }, 400, cors);

  const existing = await env.FILE_STORE.get('user:' + username.toLowerCase());
  if (existing) return json({ error: '用户名已存在' }, 409, cors);

  const userId = 'u_' + randomToken().substring(0, 16);
  const passwordHash = await sha256(password);
  await env.FILE_STORE.put('user:' + username.toLowerCase(), JSON.stringify({ userId, username, passwordHash, createdAt: new Date().toISOString() }));

  return json({ success: true }, 200, cors);
}

async function handleLogin(request, env, cors) {
  let body; try { body = await request.json(); } catch { return json({ error: '无效请求' }, 400, cors); }
  const { username, password } = body;
  if (!username || !password) return json({ error: '缺少用户名或密码' }, 400, cors);

  const userData = await env.FILE_STORE.get('user:' + username.toLowerCase(), 'json');
  if (!userData) return json({ error: '用户名或密码错误' }, 401, cors);

  const passwordHash = await sha256(password);
  if (passwordHash !== userData.passwordHash) return json({ error: '用户名或密码错误' }, 401, cors);

  const token = randomToken();
  await env.FILE_STORE.put('session:' + token, JSON.stringify({ username: userData.username, userId: userData.userId, createdAt: new Date().toISOString() }), { expirationTtl: 86400 });

  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json;charset=utf-8', 'Set-Cookie': `session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`, ...cors },
  });
}

function handleLogout(cors) {
  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json;charset=utf-8', 'Set-Cookie': 'session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0', ...cors },
  });
}

// ==================== API Key 处理 ====================

async function handleListApiKeys(userId, env, cors) {
  const prefix = 'apikey:' + userId + ':';
  const list = await env.FILE_STORE.list({ prefix });
  const keys = [];
  for (const item of list.keys) {
    const data = await env.FILE_STORE.get(item.name, 'json');
    if (data) keys.push({ id: item.name.substring(prefix.length), name: data.name, permissions: data.permissions, createdAt: data.createdAt });
  }
  return json({ keys }, 200, cors);
}

async function handleCreateApiKey(userId, username, request, env, cors) {
  // 检查数量限制
  const prefix = 'apikey:' + userId + ':';
  const list = await env.FILE_STORE.list({ prefix });
  if (list.keys.length >= 3) return json({ error: '最多创建3个 API Key' }, 400, cors);

  let body; try { body = await request.json(); } catch { return json({ error: '无效 JSON' }, 400, cors); }
  const { name, permissions } = body;
  if (!name || !permissions || !Array.isArray(permissions)) return json({ error: '缺少 name 或 permissions' }, 400, cors);

  const validPerms = ['files:read', 'files:write', 'files:delete', 'files:edit', 'scripts:read', 'scripts:write', 'scripts:execute'];
  const filteredPerms = permissions.filter(p => validPerms.includes(p));
  if (filteredPerms.length === 0) return json({ error: '至少选择一个权限' }, 400, cors);

  const apiKey = 'ak_' + randomToken();
  const keyId = 'k_' + Date.now();
  const data = { name, permissions: filteredPerms, createdAt: new Date().toISOString() };

  // 存储 API Key 数据
  await env.FILE_STORE.put('apikey:' + userId + ':' + keyId, JSON.stringify(data));
  // 存储反向查找（Key → 用户）
  await env.FILE_STORE.put('apikey_lookup:' + apiKey, JSON.stringify({ userId, username, permissions: filteredPerms }));

  return json({ id: keyId, name, key: apiKey, permissions: filteredPerms }, 200, cors);
}

async function handleDeleteApiKey(userId, keyId, env, cors) {
  const data = await env.FILE_STORE.get('apikey:' + userId + ':' + keyId, 'json');
  if (!data) return json({ error: 'API Key 不存在' }, 404, cors);

  await env.FILE_STORE.delete('apikey:' + userId + ':' + keyId);
  return json({ deleted: true }, 200, cors);
}

// ==================== 文件处理 ====================

async function handleListDir(userId, dir, env, cors) {
  const cleanDir = normalizeDir(dir);
  const prefix = userId + '/' + (cleanDir ? cleanDir + '/' : '');
  const list = await env.FILE_STORE.list({ prefix });
  const dirs = new Set(), files = [];

  for (const item of list.keys) {
    const relKey = item.name.substring(prefix.length);
    if (!relKey || relKey.endsWith('/.dir') || relKey.startsWith('.dir_markers/')) continue;
    const slashIdx = relKey.indexOf('/');
    if (slashIdx !== -1) { dirs.add(relKey.substring(0, slashIdx)); continue; }
    const m = item.metadata || {};
    files.push({ key: item.name, name: m.originalName || relKey, type: 'file', metadata: { contentType: m.contentType||'application/octet-stream', size: m.size||0, isText: m.isText||false, isImage: m.isImage||false, hasPassword: !!m.passwordHash, uploadedAt: m.uploadedAt||null } });
  }

  const dmList = await env.FILE_STORE.list({ prefix: prefix + '.dir_markers/' });
  for (const item of dmList.keys) {
    const dn = item.name.substring((prefix + '.dir_markers/').length);
    if (dn && dn.indexOf('/') === -1) dirs.add(dn);
  }

  return json({ entries: [...Array.from(dirs).map(d => ({ name: d, type: 'dir' })), ...files] }, 200, cors);
}

async function handleUpload(userId, request, env, cors) {
  const fd = await request.formData();
  const file = fd.get('file'), dir = fd.get('dir') || '', password = fd.get('password') || '';
  if (!file || !(file instanceof File)) return json({ error: '未提供文件' }, 400, cors);

  const buffer = await file.arrayBuffer();
  if (buffer.byteLength > 25 * 1024 * 1024) return json({ error: '文件超过25MB限制' }, 400, cors);

  const base64 = arrayBufferToBase64(buffer);
  const name = file.name || 'untitled';
  const contentType = file.type || 'application/octet-stream';
  const key = makeFileKey(userId, dir, name, Date.now());
  const metadata = { originalName: name, contentType, size: buffer.byteLength, isText: isTextFile(name, contentType), isImage: isImageFile(name, contentType), uploadedAt: new Date().toISOString() };
  if (password) metadata.passwordHash = await sha256(password);

  await env.FILE_STORE.put(key, base64, { metadata });
  return json({ key, name, size: buffer.byteLength }, 200, cors);
}

async function handleMkdir(userId, request, env, cors) {
  let body; try { body = await request.json(); } catch { return json({ error: '无效 JSON' }, 400, cors); }
  const dir = normalizeDir(body.dir);
  if (!dir) return json({ error: '目录名不能为空' }, 400, cors);
  await env.FILE_STORE.put(userId + '/.dir_markers/' + dir, '1', { metadata: { createdAt: new Date().toISOString() } });
  return json({ dir, created: true }, 200, cors);
}

async function handleDownload(key, password, env, cors) {
  const { value, metadata } = await env.FILE_STORE.getWithMetadata(key, 'arrayBuffer');
  if (!value) return json({ error: '文件不存在' }, 404, cors);

  if (metadata?.passwordHash) {
    if (!password) return json({ error: '需要密码', needPassword: true }, 401, cors);
    if (await sha256(password) !== metadata.passwordHash) return json({ error: '密码错误' }, 403, cors);
  }

  const base64 = new TextDecoder().decode(value);
  const bytes = base64ToBytes(base64);
  const filename = metadata?.originalName || key.split('/').pop() || key;
  return new Response(bytes, { headers: { 'Content-Type': metadata?.contentType || 'application/octet-stream', 'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`, 'Content-Length': bytes.byteLength.toString(), ...cors } });
}

async function handleGetFile(key, env, cors) {
  const { value, metadata } = await env.FILE_STORE.getWithMetadata(key, 'arrayBuffer');
  if (!value) return json({ error: '文件不存在' }, 404, cors);
  const result = { key, metadata: metadata || {} };
  if (metadata?.isText) result.content = base64ToText(new TextDecoder().decode(value));
  return json(result, 200, cors);
}

async function handleUpdate(key, request, env, cors) {
  const { value, metadata } = await env.FILE_STORE.getWithMetadata(key, 'arrayBuffer');
  if (!value) return json({ error: '文件不存在' }, 404, cors);
  if (!metadata?.isText) return json({ error: '仅支持编辑文本文件' }, 400, cors);

  let body; try { body = await request.json(); } catch { return json({ error: '无效 JSON' }, 400, cors); }
  if (typeof body.content !== 'string') return json({ error: '缺少 content' }, 400, cors);

  const contentBytes = new TextEncoder().encode(body.content);
  const newBase64 = arrayBufferToBase64(contentBytes.buffer);
  await env.FILE_STORE.put(key, newBase64, { metadata: { ...metadata, size: contentBytes.byteLength, updatedAt: new Date().toISOString() } });
  return json({ key, size: contentBytes.byteLength }, 200, cors);
}

async function handleDelete(key, env, cors) {
  await env.FILE_STORE.delete(key);
  return json({ deleted: true }, 200, cors);
}

// ==================== Admin 处理 ====================

/** 首次安装 — 创建管理员账号 */
async function handleAdminSetup(request, env, cors) {
  // 检查是否已安装
  const userList = await env.FILE_STORE.list({ prefix: 'user:', limit: 1 });
  if (userList.keys.length > 0) return json({ error: '系统已安装' }, 400, cors);

  let body; try { body = await request.json(); } catch { return json({ error: '无效请求' }, 400, cors); }
  const { username, password } = body;
  if (!username || !password) return json({ error: '缺少用户名或密码' }, 400, cors);
  if (!/^[a-zA-Z0-9]{3,20}$/.test(username)) return json({ error: '用户名需3-20位字母数字' }, 400, cors);
  if (password.length < 6) return json({ error: '密码至少6位' }, 400, cors);

  const userId = 'u_' + randomToken().substring(0, 16);
  const passwordHash = await sha256(password);
  await env.FILE_STORE.put('user:' + username.toLowerCase(), JSON.stringify({ userId, username, passwordHash, createdAt: new Date().toISOString() }));
  // 标记为管理员
  await env.FILE_STORE.put('admin:' + userId, '1');

  // 自动登录
  const token = randomToken();
  await env.FILE_STORE.put('session:' + token, JSON.stringify({ username, userId, createdAt: new Date().toISOString() }), { expirationTtl: 86400 });

  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json;charset=utf-8', 'Set-Cookie': `session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`, ...cors },
  });
}

/** 列出所有用户 */
async function handleAdminUsers(env, cors) {
  const list = await env.FILE_STORE.list({ prefix: 'user:' });
  const users = [];
  for (const item of list.keys) {
    const data = await env.FILE_STORE.get(item.name, 'json');
    if (data) {
      const isAdmin = !!(await env.FILE_STORE.get('admin:' + data.userId));
      users.push({ userId: data.userId, username: data.username, createdAt: data.createdAt, isAdmin });
    }
  }
  return json({ users }, 200, cors);
}

/** 列出所有文件（跨用户） */
async function handleAdminFiles(userIdFilter, env, cors) {
  const prefix = userIdFilter ? userIdFilter + '/' : '';
  const list = await env.FILE_STORE.list({ prefix });
  const files = [];
  for (const item of list.keys) {
    if (item.name.includes('.dir_markers/') || item.name.endsWith('/.dir')) continue;
    const m = item.metadata || {};
    // 提取 userId
    const userId = item.name.split('/')[0];
    if (!userId || !userId.startsWith('u_')) continue;
    files.push({
      key: item.name,
      name: m.originalName || item.name.split('/').pop() || item.name,
      userId,
      type: 'file',
      size: m.size || 0,
      contentType: m.contentType || '',
      isText: m.isText || false,
      isImage: m.isImage || false,
      uploadedAt: m.uploadedAt || null,
      hasPassword: !!m.passwordHash,
    });
  }
  return json({ files }, 200, cors);
}

/** 列出所有脚本（跨用户） */
async function handleAdminScripts(env, cors) {
  const list = await env.FILE_STORE.list({ prefix: 'script:' });
  const scripts = [];
  for (const item of list.keys) {
    const data = await env.FILE_STORE.get(item.name, 'json');
    if (data) {
      const parts = item.name.split(':');
      const userId = parts[1] || '';
      scripts.push({ id: parts.slice(2).join(':'), userId, name: data.name, updatedAt: data.updatedAt });
    }
  }
  return json({ scripts }, 200, cors);
}

/** 管理员删除任意文件 */
async function handleAdminDeleteFile(key, env, cors) {
  await env.FILE_STORE.delete(key);
  return json({ deleted: true }, 200, cors);
}

/** 管理员删除任意脚本 */
async function handleAdminDeleteScript(userId, scriptId, env, cors) {
  await env.FILE_STORE.delete('script:' + userId + ':' + scriptId);
  return json({ deleted: true }, 200, cors);
}

/** 管理员查看任意脚本 */
async function handleAdminGetScript(userId, scriptId, env, cors) {
  const data = await env.FILE_STORE.get('script:' + userId + ':' + scriptId, 'json');
  if (!data) return json({ error: '脚本不存在' }, 404, cors);
  return json({ id: scriptId, userId, name: data.name, code: data.code, updatedAt: data.updatedAt }, 200, cors);
}

/** 管理员编辑任意脚本 */
async function handleAdminSaveScript(userId, scriptId, request, env, cors) {
  let body; try { body = await request.json(); } catch { return json({ error: '无效 JSON' }, 400, cors); }
  const { name, code } = body;
  if (!name || code === undefined) return json({ error: '缺少 name 或 code' }, 400, cors);
  const data = { name, code, updatedAt: new Date().toISOString() };
  await env.FILE_STORE.put('script:' + userId + ':' + scriptId, JSON.stringify(data));
  return json({ id: scriptId, name }, 200, cors);
}

// ==================== 云函数处理 ====================

async function handleListScripts(userId, env, cors) {
  const prefix = 'script:' + userId + ':';
  const list = await env.FILE_STORE.list({ prefix });
  const scripts = [];
  for (const item of list.keys) {
    const data = await env.FILE_STORE.get(item.name, 'json');
    if (data) scripts.push({ id: item.name.substring(prefix.length), name: data.name, updatedAt: data.updatedAt });
  }
  return json({ scripts }, 200, cors);
}

async function handleGetScript(userId, id, env, cors) {
  const data = await env.FILE_STORE.get('script:' + userId + ':' + id, 'json');
  if (!data) return json({ error: '脚本不存在' }, 404, cors);
  return json({ id, name: data.name, code: data.code, updatedAt: data.updatedAt }, 200, cors);
}

async function handleSaveScript(userId, id, request, env, cors) {
  let body; try { body = await request.json(); } catch { return json({ error: '无效 JSON' }, 400, cors); }
  const { name, code } = body;
  if (!name || code === undefined) return json({ error: '缺少 name 或 code' }, 400, cors);

  const scriptId = id || 's_' + Date.now();
  const data = { name, code, updatedAt: new Date().toISOString() };
  await env.FILE_STORE.put('script:' + userId + ':' + scriptId, JSON.stringify(data));
  return json({ id: scriptId, name }, 200, cors);
}

/** JS 沙箱执行（基于 QuickJS WASM，支持参数） */
async function handleRun(userId, request, env, cors) {
  let body; try { body = await request.json(); } catch { return json({ error: '无效 JSON' }, 400, cors); }
  if (!body.code || typeof body.code !== 'string') return json({ error: '缺少 code' }, 400, cors);
  if (body.code.length > 50000) return json({ error: '代码过长（最大50KB）' }, 400, cors);

  // 确保 QuickJS 已初始化
  try { await getQJS(); } catch (e) { return json({ error: 'QuickJS 初始化失败: ' + e.message }, 500, cors); }

  const params = body.params || null;

  try {
    let result;
    if (params) {
      result = qjsEvalWithParams(body.code, params);
    } else {
      result = qjsEval(body.code);
    }
    // result 格式: { output: ["line1", "line2"], result: "..." }
    if (result.output && result.output.length > 0 && result.output[0] === '') {
      result.output = result.output.filter(l => l !== '');
    }
    return json({ output: result.output || [], result: result.result !== undefined && result.result !== null ? result.result : null }, 200, cors);
  } catch (e) {
    return json({ output: [], result: null, error: e.message || String(e) }, 200, cors);
  }
}

/** JS 沙箱执行 — 运行已保存的脚本（按 ID） */
async function handleRunScript(userId, scriptId, request, env, cors) {
  // 读取脚本
  const data = await env.FILE_STORE.get('script:' + userId + ':' + scriptId, 'json');
  if (!data) return json({ error: '脚本不存在' }, 404, cors);

  let body; try { body = await request.json(); } catch { body = {}; }
  if (data.code.length > 50000) return json({ error: '代码过长（最大50KB）' }, 400, cors);

  // 确保 QuickJS 已初始化
  try { await getQJS(); } catch (e) { return json({ error: 'QuickJS 初始化失败: ' + e.message }, 500, cors); }

  const params = body.params || null;

  try {
    let result;
    if (params) {
      result = qjsEvalWithParams(data.code, params);
    } else {
      result = qjsEval(data.code);
    }
    if (result.output && result.output.length > 0 && result.output[0] === '') {
      result.output = result.output.filter(l => l !== '');
    }
    return json({ script: data.name, output: result.output || [], result: result.result !== undefined && result.result !== null ? result.result : null }, 200, cors);
  } catch (e) {
    return json({ script: data.name, output: [], result: null, error: e.message || String(e) }, 200, cors);
  }
}

// ==================== 辅助 ====================

function json(data, status, headers) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json;charset=utf-8', ...headers } });
}