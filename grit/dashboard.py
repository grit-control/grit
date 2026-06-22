"""GRIT local web dashboard — the control room.

Hero metrics, live activity sparkline, kill switch, approval cards,
flight-recorder sessions with expandable call timelines, cost meter,
failure taxonomy, live audit feed with filter chips and relative times.
Stdlib-only (http.server), single file, no build step, fully offline.
Binds to 127.0.0.1 — local use only in the MVP.
"""
from __future__ import annotations

import json
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .audit import AuditLog
from .recorder import Recorder

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>GRIT — control plane</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%238b7cf6'/%3E%3Ctext x='16' y='22.5' font-family='sans-serif' font-size='17' font-weight='700' text-anchor='middle' fill='%230a0c10'%3EG%3C/text%3E%3C/svg%3E">
<style>
:root{--bg:#0a0c10;--surface:#10131a;--surface2:#151926;--line:#20263a;
--text:#e7eaf2;--dim:#8a93a6;--accent:#8b7cf6;--ok:#3fb97f;--warn:#e0a83a;
--bad:#ef5e74;--mono:ui-monospace,'Cascadia Code',Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-size:13.5px;
line-height:1.5;font-family:ui-sans-serif,-apple-system,'Segoe UI',Inter,Roboto,sans-serif}
button{font-family:inherit}
button:focus-visible,.chip:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
header{position:sticky;top:0;z-index:20;height:56px;display:flex;align-items:center;
gap:14px;padding:0 24px;background:rgba(10,12,16,.78);
backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
border-bottom:1px solid var(--line)}
.wordmark{font-size:16px;font-weight:700;letter-spacing:.01em}
.plane{font-size:9.5px;font-weight:700;letter-spacing:.18em;color:var(--dim)}
.conn{display:flex;align-items:center;gap:7px;font-size:9.5px;font-weight:700;
letter-spacing:.16em;color:var(--dim)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);
animation:pulse 2s ease-out infinite}
.dot.err{background:var(--bad);animation:none}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(63,185,127,.45)}
70%{box-shadow:0 0 0 6px rgba(63,185,127,0)}100%{box-shadow:0 0 0 0 rgba(63,185,127,0)}}
#modebadge{font-size:10px;font-weight:700;letter-spacing:.12em;padding:4px 11px;
border-radius:999px;border:1px solid var(--line)}
#modebadge.observe{color:var(--warn);background:rgba(224,168,58,.08);
border-color:rgba(224,168,58,.4)}
#modebadge.enforce{color:var(--ok);background:rgba(63,185,127,.08);
border-color:rgba(63,185,127,.4)}
.spacer{flex:1}
#kill{border:0;border-radius:8px;padding:9px 16px;font-weight:700;font-size:12px;
letter-spacing:.05em;cursor:pointer;color:#fff;background:var(--bad);
transition:transform .12s ease,filter .15s}
#kill:hover{transform:translateY(-1px);filter:brightness(1.08)}
#kill:active{transform:scale(.97)}
#kill.paused{background:var(--ok);color:#06130c}
.banner{display:none;padding:10px 24px;font-size:12.5px;font-weight:600;
border-bottom:1px solid var(--line)}
#pausebanner{background:rgba(239,94,116,.08);color:var(--bad)}
#obsbanner{background:rgba(224,168,58,.07);color:var(--warn)}
main{padding:24px 24px 56px;max-width:1240px;margin:0 auto}
.statgrid{display:grid;grid-template-columns:repeat(7,1fr);gap:12px;margin-bottom:28px}
.sparkcard{grid-column:span 2}
@media(max-width:1100px){.statgrid{grid-template-columns:repeat(3,1fr)}
.sparkcard{grid-column:span 3}}
@media(max-width:640px){.statgrid{grid-template-columns:repeat(2,1fr)}
.sparkcard{grid-column:span 2}}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;
padding:14px 16px;transition:border-color .15s}
.card:hover{border-color:#2a3148}
.tablecard{padding:4px 10px;overflow-x:auto}
.label{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;
color:var(--dim)}
.stat .value{font-size:29px;font-weight:700;margin-top:6px;letter-spacing:-.01em;
font-variant-numeric:tabular-nums}
.stat .sub{font-size:11.5px;color:var(--dim);margin-top:1px}
.stat .value.warn{color:var(--warn)}
.sparkcard svg{width:100%;height:62px;margin-top:8px;display:block}
section{margin-bottom:30px}
h2{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.12em;
color:var(--dim);margin:0 0 10px 2px}
h2 .note{text-transform:none;letter-spacing:0;font-weight:500}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);
vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase;
letter-spacing:.07em;white-space:nowrap}
tr:last-child td{border-bottom:0}
tbody tr{transition:background .12s}
tbody tr:hover{background:var(--surface2)}
td.args{font-family:var(--mono);font-size:12px;color:#a9b1c4;max-width:360px;
overflow-wrap:anywhere}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
td.dimcell,span.dimcell{color:var(--dim);font-variant-numeric:tabular-nums;
white-space:nowrap}
.badge{padding:2px 9px;border-radius:999px;font-size:11px;font-weight:650;
white-space:nowrap}
.executed,.executed_after_approval,.executed_shadow,.allow,.approved{
background:rgba(63,185,127,.12);color:var(--ok)}
.executed_shadow{outline:1px dashed rgba(63,185,127,.45)}
.blocked,.deny,.approval_denied,.approval_timeout,.denied{
background:rgba(239,94,116,.12);color:var(--bad)}
.approve,.pending{background:rgba(224,168,58,.12);color:var(--warn)}
.error{background:rgba(139,124,246,.12);color:var(--accent)}
.tag{border:1px solid var(--line);border-radius:6px;padding:1px 7px;
font-size:10.5px;color:var(--dim);white-space:nowrap}
.risk-low{color:var(--ok)}.risk-medium{color:var(--warn)}
.risk-high{color:#ec8246}.risk-critical{color:var(--bad);font-weight:700}
.approval-card{display:flex;align-items:center;gap:18px;margin-bottom:10px;
border-left:3px solid var(--warn)}
.approval-card .grow{flex:1;min-width:0}
.approval-card .tool{font-weight:700;font-size:14px}
.approval-card .why{color:var(--dim);font-size:12.5px;margin-top:2px}
.approval-card .args{font-family:var(--mono);font-size:12px;color:#a9b1c4;
margin-top:5px;overflow-wrap:anywhere}
@media(max-width:760px){.approval-card{flex-wrap:wrap}
.approval-card .grow{flex-basis:100%;order:-1}}
.risknum{font-size:24px;font-weight:700;min-width:54px;text-align:center;
font-variant-numeric:tabular-nums}
.risknum small{display:block;font-size:9px;color:var(--dim);font-weight:700;
letter-spacing:.14em}
.btn{border:0;border-radius:8px;padding:9px 18px;font-weight:700;font-size:12.5px;
cursor:pointer;color:#fff;transition:transform .12s ease,filter .15s}
.btn:hover{transform:translateY(-1px);filter:brightness(1.08)}
.btn:active{transform:scale(.97)}
.btn.ok{background:var(--ok);color:#06130c}.btn.no{background:var(--bad)}
.chips{display:flex;gap:6px;margin:0 0 10px;flex-wrap:wrap}
.chip{border:1px solid var(--line);background:var(--surface);color:var(--dim);
font-size:11.5px;font-weight:600;padding:4px 13px;border-radius:999px;
cursor:pointer;transition:color .12s,border-color .12s,transform .12s}
.chip:hover{color:var(--text);border-color:#2c3550}
.chip:active{transform:scale(.97)}
.chip.active{background:var(--accent);border-color:var(--accent);color:#0a0c10}
.minibar{height:4px;background:var(--surface2);border-radius:2px;margin-top:5px;
min-width:48px;overflow:hidden}
.minibar div{height:4px;background:var(--accent);border-radius:2px}
.empty{color:#5b6478;padding:14px 12px;font-size:13px}
.sessrow{cursor:pointer}
.chev{display:inline-block;transition:transform .15s;color:var(--dim);margin-right:8px}
.open .chev{transform:rotate(90deg)}
.tracewrap{background:var(--surface2);border:1px solid var(--line);
border-radius:10px;margin:4px 0 10px;padding:4px 10px;overflow-x:auto}
.tracewrap table{font-size:12px}
.tracewrap th,.tracewrap td{padding:6px 10px}
tr.rownew{animation:rowin 1.2s ease-out}
@keyframes rowin{from{background:rgba(139,124,246,.16)}to{background:transparent}}
#toasts{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;
gap:8px;z-index:50}
.toast{background:var(--surface2);border:1px solid var(--line);
border-left:3px solid var(--accent);border-radius:10px;padding:10px 14px;
font-size:12.5px;font-weight:600;max-width:340px;overflow-wrap:anywhere;
animation:slidein .25s ease}
.toast.ok{border-left-color:var(--ok)}.toast.bad{border-left-color:var(--bad)}
@keyframes slidein{from{transform:translateX(24px);opacity:0}
to{transform:none;opacity:1}}
footer{color:#4c5468;font-size:12px;text-align:center;padding:28px 0 12px}
@media(prefers-reduced-motion:reduce){
.dot,.toast,tr.rownew{animation:none}
*{transition:none!important}}
</style></head><body>
<header>
  <span class="wordmark">GRIT</span>
  <span class="plane">CONTROL PLANE</span>
  <span class="conn"><span id="conn" class="dot" title="live"></span>LIVE</span>
  <span id="modebadge"></span>
  <span class="spacer"></span>
  <button id="kill">PAUSE ALL AGENTS</button>
</header>
<div id="pausebanner" class="banner">GATEWAY PAUSED — every tool call is being refused</div>
<div id="obsbanner" class="banner"></div>
<main>
<div class="statgrid">
  <div class="card stat"><div class="label">Events · 7d</div>
    <div class="value" id="st-events">–</div>
    <div class="sub">calls through the gateway</div></div>
  <div class="card stat"><div class="label">Sessions</div>
    <div class="value" id="st-sessions">–</div>
    <div class="sub">flight recordings</div></div>
  <div class="card stat"><div class="label">Pending</div>
    <div class="value" id="st-pending">–</div>
    <div class="sub">waiting for a human</div></div>
  <div class="card stat"><div class="label">Tool cost</div>
    <div class="value" id="st-cost">–</div>
    <div class="sub">est. context through tools</div></div>
  <div class="card stat"><div class="label">Failures</div>
    <div class="value" id="st-fail">–</div>
    <div class="sub">all classes</div></div>
  <div class="card stat sparkcard"><div class="label">Activity · 24h</div>
    <div id="spark"></div></div>
</div>

<section><h2>Pending approvals</h2><div id="pending"></div></section>

<section><h2>Sessions — flight recorder <span class="note">(click a row for the call timeline)</span></h2>
<div class="card tablecard">
<table id="sessions"><thead><tr><th>Session</th><th>Started</th>
<th class="num">Calls</th><th class="num">Failures</th>
<th class="num">Est. tokens</th></tr></thead><tbody></tbody></table></div></section>

<section><h2>Tool operations</h2><div class="card tablecard">
<table id="stats"><thead><tr><th>Tool</th><th class="num">Calls</th>
<th class="num">Executed</th><th class="num">Blocked</th><th class="num">Errors</th>
<th class="num">Avg ms</th><th class="num">Avg risk</th><th class="num">Max risk</th>
</tr></thead><tbody></tbody></table></div></section>

<section><h2>Cost meter</h2><div class="card tablecard">
<table id="costs"><thead><tr><th>Tool</th><th class="num">Calls</th>
<th class="num">Tokens in</th><th class="num">Tokens out</th>
<th class="num">Est. USD</th></tr></thead><tbody></tbody></table></div></section>

<section><h2>Failure taxonomy</h2><div class="card tablecard">
<table id="failures"><thead><tr><th>Class</th><th class="num">Count</th>
</tr></thead><tbody></tbody></table></div></section>

<section><h2>Recent calls</h2>
<div class="chips" id="chips">
  <button class="chip active" data-f="all">All</button>
  <button class="chip" data-f="executed">Executed</button>
  <button class="chip" data-f="blocked">Blocked</button>
  <button class="chip" data-f="held">Held</button>
  <button class="chip" data-f="errors">Errors</button>
</div>
<div class="card tablecard">
<table id="recent"><thead><tr><th>Time</th><th>Age</th><th>Tool</th>
<th>Arguments</th><th>Decision</th><th>Status</th><th class="num">Risk</th>
<th>Rule</th></tr></thead><tbody></tbody></table></div></section>
<footer>GRIT v__VERSION__ — every agent action: decided, recorded, replayable</footer>
</main>
<div id="toasts"></div>
<script>
let paused=false,filter='all',lastMaxId=null,freshIds=new Set();
let lastState={sessions:[],recent:[],pending:[]};
const openSessions=new Set(),traces={};
const ESCMAP={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
function esc(s){return String(s).replace(/[&<>"']/g,c=>ESCMAP[c])}
function riskCls(r){if(r===null||r===undefined)return'';
  return r>=85?'risk-critical':r>=60?'risk-high':r>=30?'risk-medium':'risk-low'}
function riskCell(r){return '<td class="num '+riskCls(r)+'">'+
  (r===null||r===undefined?'-':r)+'</td>'}
function nowSec(){return lastState.now||Date.now()/1000}
function rel(ts){const d=Math.max(0,nowSec()-ts);
  if(d<60)return Math.floor(d)+'s ago';
  if(d<3600)return Math.floor(d/60)+'m ago';
  if(d<86400)return Math.floor(d/3600)+'h ago';
  return Math.floor(d/86400)+'d ago'}
function setConn(ok){const d=document.getElementById('conn');
  d.className='dot'+(ok?'':' err');d.title=ok?'live':'connection lost'}
function toast(msg,cls){const t=document.createElement('div');
  t.className='toast'+(cls?' '+cls:'');t.textContent=msg;
  document.getElementById('toasts').appendChild(t);
  setTimeout(()=>t.remove(),3000)}
async function decide(id,decision,tool){
  try{await fetch('/api/decide',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id:id,decision:decision})});
  }catch(e){setConn(false);return}
  toast((decision==='approved'?'Approved ':'Denied ')+tool,
        decision==='approved'?'ok':'bad');
  refresh()}
async function toggle(){
  const target=!paused;
  try{await fetch('/api/pause',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({paused:target})});
  }catch(e){setConn(false);return}
  toast(target?'Gateway paused — every call will be refused'
              :'Gateway resumed — calls are flowing',target?'bad':'ok');
  refresh()}
function spark(data){
  const w=560,h=62,max=Math.max.apply(null,data.concat([1]));
  const n=Math.max(data.length-1,1);
  const pts=data.map((v,i)=>[(i/n)*w,h-4-(v/max)*(h-14)]);
  const line=pts.map(p=>p[0].toFixed(1)+','+p[1].toFixed(1)).join(' ');
  const lp=pts[pts.length-1];
  return '<svg viewBox="0 0 '+w+' '+h+'" preserveAspectRatio="none" aria-hidden="true">'+
   '<defs><linearGradient id="sg" x1="0" y1="0" x2="0" y2="1">'+
   '<stop offset="0%" stop-color="#8b7cf6" stop-opacity="0.4"/>'+
   '<stop offset="100%" stop-color="#8b7cf6" stop-opacity="0"/></linearGradient></defs>'+
   '<polygon points="'+line+' '+w+','+h+' 0,'+h+'" fill="url(#sg)"/>'+
   '<polyline points="'+line+'" fill="none" stroke="#8b7cf6" stroke-width="2" '+
   'stroke-linejoin="round" stroke-linecap="round"/>'+
   '<circle cx="'+lp[0].toFixed(1)+'" cy="'+lp[1].toFixed(1)+'" r="3" fill="#8b7cf6"/>'+
   '</svg>'}
function traceTable(rows){
  if(!rows||!rows.length)return '<div class="empty">no recorded calls</div>';
  return '<table><thead><tr><th>#</th><th>Time</th><th>Status</th><th>Class</th>'+
   '<th>Tool</th><th class="num">ms</th><th class="num">tokens</th><th>Arguments</th>'+
   '</tr></thead><tbody>'+rows.map(r=>
   '<tr><td class="dimcell">'+r.seq+'</td>'+
   '<td class="dimcell">'+new Date(r.ts*1000).toLocaleTimeString()+'</td>'+
   '<td><span class="badge '+esc(r.status)+'">'+esc(r.status)+'</span></td>'+
   '<td>'+(r.failure_class?'<span class="tag">'+esc(r.failure_class)+'</span>'
                          :'<span class="dimcell">-</span>')+'</td>'+
   '<td>'+esc(r.tool)+'</td>'+
   '<td class="num">'+(r.latency_ms===null?'-':r.latency_ms)+'</td>'+
   '<td class="num">'+(r.tokens_in+r.tokens_out)+'</td>'+
   '<td class="args">'+esc(r.arguments)+'</td></tr>').join('')+'</tbody></table>'}
async function toggleSession(sid){
  if(openSessions.has(sid)){openSessions.delete(sid)}
  else{openSessions.add(sid);
    try{const r=await fetch('/api/trace?session='+encodeURIComponent(sid));
      traces[sid]=(await r.json()).trace;
    }catch(e){setConn(false);return}}
  renderSessions(lastState)}
function renderSessions(s){
  const se=document.querySelector('#sessions tbody');
  if(!s.sessions.length){
    se.innerHTML='<tr><td colspan="5" class="empty">No recorded sessions yet — point an agent at the gateway and they appear here</td></tr>';
    return}
  se.innerHTML=s.sessions.map(x=>{
    const open=openSessions.has(x.session_id);
    let row='<tr class="sessrow'+(open?' open':'')+'" data-sid="'+esc(x.session_id)+'">'+
     '<td><span class="chev">&#9656;</span><span style="font-family:var(--mono)">'+
     esc(x.session_id)+'</span></td>'+
     '<td class="dimcell">'+new Date(x.started*1000).toLocaleString()+'</td>'+
     '<td class="num">'+x.calls+'</td><td class="num">'+x.failures+
     '</td><td class="num">'+x.est_tokens+'</td></tr>';
    if(open){row+='<tr><td colspan="5"><div class="tracewrap">'+
     traceTable(traces[x.session_id])+'</div></td></tr>'}
    return row}).join('')}
function matchesFilter(st){
  if(filter==='executed')return st.indexOf('executed')===0;
  if(filter==='blocked')return st==='blocked';
  if(filter==='held')return st==='approval_denied'||st==='approval_timeout';
  if(filter==='errors')return st==='error';
  return true}
function renderRecent(s){
  const t=document.querySelector('#recent tbody');
  if(!s.recent.length){
    t.innerHTML='<tr><td colspan="8" class="empty">No calls yet</td></tr>';return}
  const rows=s.recent.filter(e=>matchesFilter(e.status));
  if(!rows.length){
    t.innerHTML='<tr><td colspan="8" class="empty">No calls match this filter</td></tr>';return}
  t.innerHTML=rows.map(e=>
   '<tr'+(freshIds.has(e.id)?' class="rownew"':'')+'>'+
   '<td class="dimcell">'+new Date(e.ts*1000).toLocaleTimeString()+'</td>'+
   '<td class="dimcell">'+rel(e.ts)+'</td>'+
   '<td>'+esc(e.tool)+'</td>'+
   '<td class="args">'+esc(e.arguments)+'</td>'+
   '<td><span class="badge '+esc(e.decision)+'">'+esc(e.decision)+'</span></td>'+
   '<td><span class="badge '+esc(e.status)+'">'+esc(e.status)+'</span></td>'+
   riskCell(e.risk_score)+
   '<td class="dimcell">'+esc(e.rule_id||'-')+'</td></tr>').join('')}
async function refresh(){
  let s;
  try{const r=await fetch('/api/state');s=await r.json();setConn(true)}
  catch(e){setConn(false);return}
  let maxId=lastMaxId;
  freshIds=new Set();
  s.recent.forEach(e=>{
    if(lastMaxId!==null&&e.id>lastMaxId)freshIds.add(e.id);
    if(maxId===null||e.id>maxId)maxId=e.id});
  lastMaxId=maxId;
  lastState=s;paused=s.paused;
  document.title=(s.pending.length?'('+s.pending.length+') ':'')+'GRIT';
  const b=document.getElementById('kill');
  b.className=paused?'paused':'';
  b.textContent=paused?'RESUME AGENTS':'PAUSE ALL AGENTS';
  document.getElementById('pausebanner').style.display=paused?'block':'none';
  const badge=document.getElementById('modebadge');
  badge.textContent=s.mode.toUpperCase();badge.className=s.mode;
  const ob=document.getElementById('obsbanner');
  if(s.mode==='observe'){
    ob.textContent='OBSERVE MODE — nothing is blocked; '+s.shadow+' call'+
      (s.shadow===1?'':'s')+' would have been held or denied. Set "mode": "enforce" when convinced.';
    ob.style.display='block';
  }else{ob.style.display='none'}
  document.getElementById('st-events').textContent=s.events_7d;
  document.getElementById('st-sessions').textContent=s.sessions.length;
  const pe=document.getElementById('st-pending');
  pe.textContent=s.pending.length;pe.className='value'+(s.pending.length?' warn':'');
  const cost=s.costs.reduce((a,c)=>a+c.est_usd,0);
  document.getElementById('st-cost').textContent='$'+cost.toFixed(2);
  const fails=s.failures.reduce((a,f)=>a+f.count,0);
  document.getElementById('st-fail').textContent=fails;
  document.getElementById('spark').innerHTML=spark(s.activity);
  const p=document.getElementById('pending');
  p.innerHTML=s.pending.length?s.pending.map(a=>
   '<div class="card approval-card"><div class="risknum '+riskCls(a.risk_score)+'">'+
   (a.risk_score===null||a.risk_score===undefined?'-':a.risk_score)+
   '<small>RISK</small></div>'+
   '<div class="grow"><div class="tool">'+esc(a.tool)+'</div>'+
   '<div class="why">'+esc(a.reason||'held by policy')+'</div>'+
   '<div class="args">'+esc(a.arguments)+'</div></div>'+
   '<button class="btn ok" data-id="'+a.id+'" data-decision="approved" data-tool="'+
   esc(a.tool)+'">Approve</button>'+
   '<button class="btn no" data-id="'+a.id+'" data-decision="denied" data-tool="'+
   esc(a.tool)+'">Deny</button></div>'
  ).join(''):'<div class="card"><div class="empty">No calls waiting for approval — agents are inside their guardrails</div></div>';
  renderSessions(s);
  const st=document.querySelector('#stats tbody');
  const maxCalls=s.stats.reduce((m,t2)=>Math.max(m,t2.calls),1);
  st.innerHTML=s.stats.length?s.stats.map(t2=>{
   const pct=Math.max(2,Math.round(t2.calls/maxCalls*100));
   return '<tr><td>'+esc(t2.tool)+'</td>'+
   '<td class="num">'+t2.calls+
   '<div class="minibar"><div style="width:'+pct+'%"></div></div></td>'+
   '<td class="num">'+t2.executed+'</td><td class="num">'+t2.blocked+
   '</td><td class="num">'+t2.errors+'</td>'+
   '<td class="num">'+(t2.avg_latency_ms===null?'-':t2.avg_latency_ms)+'</td>'+
   riskCell(t2.avg_risk)+riskCell(t2.max_risk)+'</tr>'}
  ).join(''):'<tr><td colspan="8" class="empty">No calls yet</td></tr>';
  const co=document.querySelector('#costs tbody');
  co.innerHTML=s.costs.length?s.costs.map(c=>
   '<tr><td>'+esc(c.tool)+'</td><td class="num">'+c.calls+'</td><td class="num">'+
   c.tokens_in+'</td><td class="num">'+c.tokens_out+'</td><td class="num">$'+
   c.est_usd.toFixed(4)+'</td></tr>'
  ).join(''):'<tr><td colspan="5" class="empty">No recorded calls yet</td></tr>';
  const fa=document.querySelector('#failures tbody');
  fa.innerHTML=s.failures.length?s.failures.map(f=>
   '<tr><td><span class="badge blocked">'+esc(f.failure_class)+'</span></td>'+
   '<td class="num">'+f.count+'</td></tr>'
  ).join(''):'<tr><td colspan="2" class="empty">No failures recorded — nice</td></tr>';
  renderRecent(s)}
document.getElementById('kill').addEventListener('click',toggle);
document.getElementById('pending').addEventListener('click',e=>{
  const b=e.target.closest('button[data-decision]');
  if(b)decide(parseInt(b.getAttribute('data-id'),10),
              b.getAttribute('data-decision'),b.getAttribute('data-tool'))});
document.getElementById('chips').addEventListener('click',e=>{
  const b=e.target.closest('button[data-f]');
  if(!b)return;
  filter=b.getAttribute('data-f');
  document.querySelectorAll('#chips .chip').forEach(c=>
    c.classList.toggle('active',c===b));
  renderRecent(lastState)});
document.querySelector('#sessions tbody').addEventListener('click',e=>{
  const tr=e.target.closest('tr.sessrow');
  if(tr)toggleSession(tr.getAttribute('data-sid'))});
refresh();setInterval(refresh,2000);
</script></body></html>"""


def make_handler(audit: AuditLog, recorder: Recorder):
    page = PAGE.replace("__VERSION__", __version__).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload) -> None:
            self._send(200, json.dumps(payload).encode("utf-8"),
                       "application/json")

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/":
                self._send(200, page, "text/html; charset=utf-8")
            elif parsed.path == "/api/state":
                self._json({"paused": audit.is_paused(),
                            "mode": audit.get_control("mode", "enforce"),
                            "shadow": audit.shadow_count(),
                            "events_7d": audit.events_count(),
                            "activity": audit.events_histogram(24),
                            "pending": audit.pending_approvals(),
                            "stats": audit.stats(),
                            "recent": audit.recent(50),
                            "sessions": recorder.sessions()[:20],
                            "costs": recorder.costs(),
                            "failures": audit.failure_breakdown(),
                            "now": time.time()})
            elif parsed.path == "/api/trace":
                query = urllib.parse.parse_qs(parsed.query)
                sid = (query.get("session") or [""])[0]
                self._json({"trace": recorder.trace(sid)})
            else:
                self._send(404, b"not found", "text/plain")

        def do_POST(self):
            # CSRF guard: a browser cross-origin/DNS-rebinding POST would carry
            # a foreign Origin; reject it so a random web page can't flip the
            # kill switch or approve a held call. Absent Origin = CLI/curl, fine.
            origin = self.headers.get("Origin")
            if origin is not None and urllib.parse.urlparse(origin).hostname \
                    not in ("127.0.0.1", "localhost", "::1"):
                self._send(403, b"cross-origin request rejected", "text/plain")
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                if self.path == "/api/decide":
                    ok = audit.decide_approval(int(body["id"]),
                                               body["decision"],
                                               decided_by="dashboard")
                elif self.path == "/api/pause":
                    audit.set_paused(bool(body["paused"]), by="dashboard")
                    ok = True
                else:
                    self._send(404, b"not found", "text/plain")
                    return
            except (KeyError, ValueError, json.JSONDecodeError) as exc:
                self._send(400, str(exc).encode("utf-8"), "text/plain")
                return
            self._json({"ok": ok})

    return Handler


def run_dashboard(db_path: str, port: int = 8787) -> None:
    server = make_server(db_path, port)
    print(f"GRIT dashboard: http://127.0.0.1:{server.server_address[1]}")
    server.serve_forever()


def make_server(db_path: str, port: int = 8787) -> ThreadingHTTPServer:
    """Build (but don't start) the dashboard server. Port 0 = ephemeral."""
    audit = AuditLog(db_path)
    recorder = Recorder(db_path)
    return ThreadingHTTPServer(("127.0.0.1", port),
                               make_handler(audit, recorder))
