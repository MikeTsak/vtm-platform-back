// logger.js – human friendly + emoji edition
const fs = require('fs');
const crypto = require('crypto');
const util = require('util');
const colors = require('colors/safe'); // install via npm i colors

// --- Environment configuration ---
const USE_JSON  = process.env.LOG_JSON === '1';
const USE_EMOJI = process.env.LOG_EMOJI !== '0';
const LEVEL     = (process.env.LOG_LEVEL || 'debug').toLowerCase();
const LOG_FILE  = process.env.LOG_FILE || '';
const TAP_CONSOLE = process.env.LOG_TAP_CONSOLE === '1';

const LEVEL_RANK = { debug: 10, info: 20, warn: 30, error: 40 };
const allow = (lvl) => LEVEL_RANK[lvl] >= LEVEL_RANK[LEVEL];

const EMO = {
  start:'🚀', auth:'🔐', char:'🧛', xp:'✨', dt:'🕰️', dom:'🏰', adm:'🛡️',
  ok:'✅', warn:'⚠️', err:'💥', req:'➡️', res:'⬅️', mail:'✉️', db:'🗄️',
  info:'ℹ️', http:'🌐', dbg:'🐛'
};

const SENSITIVE_KEYS = [
  'password','pass','pwd','authorization','cookie','token',
  'secret','key','x-api-key','set-cookie'
];

// ---------- helpers ----------
function redact(value, depth=0) {
  if (value==null || depth>5) return value;
  if (Array.isArray(value)) return value.map(v=>redact(v,depth+1));
  if (typeof value==='object') {
    const out={};
    for (const [k,v] of Object.entries(value)){
      const low=k.toLowerCase();
      out[k]=SENSITIVE_KEYS.some(s=>low.includes(s))?'[redacted]':redact(v,depth+1);
    }
    return out;
  }
  return value;
}

function writeFile(line){
  if (!LOG_FILE) return;
  fs.appendFile(LOG_FILE,line+'\n',()=>{});
}

function stamp(){ return new Date().toLocaleTimeString('en-GB',{hour12:false}); }

// pretty printer for human mode
function prettyLine(level, cat, msg, ctx) {
  const emoji = USE_EMOJI && EMO[cat] ? EMO[cat]+' ' : '';
  let colorFn = colors.white;
  if (level==='error') colorFn=colors.red;
  else if (level==='warn') colorFn=colors.yellow;
  else if (level==='info') colorFn=colors.cyan;
  else if (level==='debug') colorFn=colors.gray;

  const head = `${colors.gray(stamp())} ${colorFn(level.toUpperCase())} ${emoji}${msg}`;
  if (!ctx) return head;
  const body = util.inspect(redact(ctx), { colors:true, depth:3, breakLength:120 });
  return `${head}\n${colors.gray('└─')} ${body}`;
}

// core emitter
function emit(level, cat, msg, ctx){
  if(!allow(level)) return;
  const payload = { time:new Date().toISOString(), level, cat, msg, ...(ctx?redact(ctx):{}) };

  if(USE_JSON){
    const line = JSON.stringify(payload);
    console.log(line);
    writeFile(line);
  } else {
    const line = prettyLine(level,cat,msg,ctx);
    if(level==='error') console.error(line);
    else if(level==='warn') console.warn(line);
    else console.log(line);
    writeFile(`${payload.time} [${level.toUpperCase()}] ${msg}`);
  }
}

// ---------- exported categories ----------
const log = {
  debug:(m,c)=>emit('debug','dbg',m,c),
  start:(m,c)=>emit('info','start',m,c),
  auth:(m,c)=>emit('info','auth',m,c),
  char:(m,c)=>emit('info','char',m,c),
  xp:(m,c)=>emit('info','xp',m,c),
  dt:(m,c)=>emit('info','dt',m,c),
  dom:(m,c)=>emit('info','dom',m,c),
  adm:(m,c)=>emit('info','adm',m,c),
  ok:(m,c)=>emit('info','ok',m,c),
  info:(m,c)=>emit('info','info',m,c),
  warn:(m,c)=>emit('warn','warn',m,c),
  err:(m,c)=>emit('error','err',m,c),
  mail:(m,c)=>emit('info','mail',m,c),
  db:(m,c)=>emit('info','db',m,c),
  req:(m,c)=>emit('info','req',m,c),
  res:(m,c)=>emit('info','res',m,c),
  http:(m,c)=>emit('info','http',m,c),
};

// ---------- express middleware ----------
function attachRequestLogger() {
  return (req,res,next)=>{
    const t0 = Date.now();
    const reqCtx = {
      ip:req.ip,
      method:req.method,
      url:req.originalUrl,
      ua:req.get('user-agent'),
      body:req.body
    };
    log.req(`${req.method} ${req.originalUrl}`,reqCtx);
    res.on('finish',()=>{
      const ms = Date.now()-t0;
      const lvl = res.statusCode>=500?'err':res.statusCode>=400?'warn':'ok';
      const msg = `${res.statusCode} ${req.method} ${req.originalUrl} (${ms}ms)`;
      log[lvl](msg,{bytes:res.getHeader('content-length')});
    });
    next();
  };
}

function expressErrorHandler(){
  return (err,req,res,_next)=>{
    log.err('Unhandled API error',{url:req?.originalUrl,message:err?.message,stack:err?.stack});
    res.status(500).json({error:'Internal server error'});
  };
}

function installProcessHandlers(){
  process.on('unhandledRejection',(r)=>log.err('Unhandled Rejection',{reason:String(r)}));
  process.on('uncaughtException',(e)=>{
    log.err('Uncaught Exception',{message:e.message,stack:e.stack});
    setTimeout(()=>process.exit(1),100);
  });
}

// optionally tap console.*
function tapConsole(){
  if(!TAP_CONSOLE) return;
  ['log','warn','error'].forEach(k=>{
    const orig=console[k].bind(console);
    console[k]=(...a)=>{ log.info(a.join(' ')); orig(...a); };
  });
}
tapConsole();

module.exports={ log, attachRequestLogger, expressErrorHandler, installProcessHandlers };
