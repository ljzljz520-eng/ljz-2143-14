async function getJson(url){ const r=await fetch(url,{cache:'no-store'}); if(!r.ok) throw new Error(await r.text()); return r.json(); }
function esc(s){ return String(s ?? '').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
async function refresh(){
  const [packages,releases,inventory,diag]=await Promise.all([getJson('/api/packages'),getJson('/api/releases'),getJson('/api/inventory'),getJson('/api/diagnostics')]);
  document.querySelector('#packages').textContent=packages.map(p=>`${p.version}\n  ${p.package_id}\n  ${p.size} bytes`).join('\n\n') || '无';
  document.querySelector('#releases').textContent=releases.map(r=>`${r.group_id} ${r.state}\n  release=${r.release_id}\n  package=${r.package_id}`).join('\n\n') || '无';
  document.querySelector('#inventory tbody').innerHTML=inventory.length ? inventory.map(x=>`<tr><td>${esc(x.logical_path)}</td><td>${esc(x.media_type)}</td><td>${x.width&&x.height?esc(x.width+' × '+x.height):'矢量/无固定尺寸'}</td><td>${esc(x.layout_dependencies)}</td><td>${esc(x.version)}<br>${esc(x.releases||'未发布')}</td></tr>`).join('') : '<tr><td colspan="5">无</td></tr>';
  const tbody=document.querySelector('#diag tbody');
  tbody.innerHTML=diag.length ? diag.map(d=>`<tr><td>${esc(d.source||'server scan')}</td><td>${esc(d.group_id)} / ${esc(d.state||'')}</td><td>${esc(d.version||'')}</td><td>${esc(d.path||d.logical_path||'')}</td><td>${esc((d.reasons||[d.reason]).join('; '))}</td><td>${esc(d.expected_sha256||'')}</td></tr>`).join('') : '<tr><td colspan="6">未发现缺文件或指纹问题</td></tr>';
}
refresh().catch(e=>document.querySelector('#diag tbody').innerHTML=`<tr><td colspan="6">${esc(e.message)}</td></tr>`);
setInterval(refresh,5000);
