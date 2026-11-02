'use strict';
function readComponents() {
  const result={};
  for (const input of document.querySelectorAll('[data-component]')) result[input.dataset.component]=input.checked;
  result.max_network_pages=Number($('limit-pages').value);
  result.max_navigation_depth=Number($('limit-depth').value);
  result.max_network_seconds=Number($('limit-seconds').value);
  return result;
}
function saveComponents() {
  try { localStorage.setItem('antiphish-components-v2',JSON.stringify({profile:$('profile').value,network:$('network').value,options:readComponents()})); } catch {}
}
function preset(profile) {
  if (profile==='custom') return;
  for (const input of document.querySelectorAll('[data-component]')) {
    const key=input.dataset.component;
    input.checked=['llm','text_model','laya'].includes(key)?profile==='deep':['siglip','logo_references'].includes(key)?false:['ocr','qr','visual_brands','render_local'].includes(key)?profile!=='fast':true;
  }
}
$('profile').addEventListener('change',()=>{preset($('profile').value);saveComponents();});
$('network').addEventListener('change',saveComponents);
for (const input of document.querySelectorAll('[data-component],.limits input')) input.addEventListener('change',()=>{
  $('profile').value='custom'; saveComponents();
});
preset($('profile').value);
try {
  const saved=JSON.parse(localStorage.getItem('antiphish-components-v2') || 'null');
  if (saved?.options) {
    if (['fast','quality','deep','custom'].includes(saved.profile)) $('profile').value=saved.profile;
    if (['offline','http','browser'].includes(saved.network)) $('network').value=saved.network;
    $('browser-confirm').hidden=$('network').value!=='browser';
    for (const input of document.querySelectorAll('[data-component]')) if (typeof saved.options[input.dataset.component]==='boolean') input.checked=saved.options[input.dataset.component];
    for (const [id,key] of [['limit-pages','max_network_pages'],['limit-depth','max_navigation_depth'],['limit-seconds','max_network_seconds']]) if (Number.isInteger(saved.options[key])) $(id).value=saved.options[key];
  }
} catch {}
let kbKind='reviews', kbOffset=0, kbTotal=0;
const kbChanges=[];
const kbDescriptions={
 templates:'Структура HTML, текст и поля. Совпадение даёт предупреждение.',
 hashes:'Точные SHA256. Корпусные записи не блокируют письмо без подтверждения.',
 iocs:'Подтверждённые URL. Совпадение даёт PHISHING; правило относится к адресу, а не ко всему домену.'
};
function rememberChange(value) {
  kbChanges.push(value.change_id); $('kb-undo').hidden=false;
}
async function loadEntries() {
  const manual=kbKind==='reviews';
  $('samples').hidden=!manual; $('kb-browser').hidden=manual;
  for (const button of document.querySelectorAll('[data-kb-kind]')) button.classList.toggle('active',button.dataset.kbKind===kbKind);
  if (manual) return;
  $('kb-description').textContent=kbDescriptions[kbKind];
  $('kb-add-form').hidden=kbKind==='templates';
  $('kb-add-value').placeholder=kbKind==='hashes'?'64 символа SHA256':'https://example.ru/exact/path';
  const data=await api('/knowledge/entries/'+kbKind+'?q='+encodeURIComponent($('kb-query').value)+'&offset='+kbOffset+'&limit=30');
  kbTotal=data.total;
  if (kbOffset>=kbTotal && kbOffset>0) {kbOffset=Math.max(0,kbOffset-30);return loadEntries();}
  function labelFor(row) {
    if (row.label) return ['phishing','benign'].includes(row.label)?row.label:'unreviewed';
    return row.verdict==='BENIGN'?'benign':row.provenance==='provider-labelled-phishing-sample'?'unreviewed':'phishing';
  }
  const rows=data.rows.map(row=>{
    const category=kbKind==='templates'?(row.brand || 'Без указанного бренда'):kbKind==='hashes'?(row.object_type || 'Файл'):'URL';
    const identifier=row.value || row.sha256 || '';
    const descriptor=el('div',{},[el('strong',{},category),el('div',{class:'small url-text',title:identifier},kbKind==='iocs'?identifier:identifier.slice(0,20)+'...')]);
    if (kbKind==='templates') {
      let types=[];try{types=JSON.parse(row.sensitive_types);}catch{}
      descriptor.append(el('div',{class:'small muted'},types.length?'Поля: '+types.join(', '):'Чувствительных полей нет'));
    }
    const source=el('div',{class:'small'},[el('div',{class:'url-text'},row.source_id || row.source),el('span',{class:'muted'},row.provenance || '')]);
    const controls=el('div',{class:'row-actions'});
    if (kbKind!=='iocs') {
      const select=el('select',{'aria-label':'Метка записи '+row.id},[el('option',{value:'unreviewed'},'Непроверено'),el('option',{value:'phishing'},'Фишинговый'),el('option',{value:'benign'},'Легитимный')]);
      select.value=labelFor(row);
      select.addEventListener('change',runAction(async()=>{
        rememberChange(await api('/knowledge/entries/'+kbKind+'/'+row.id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:select.value})}));
        await loadKnowledge(); notice('Метка изменена. Её можно отменить.');
      }));
      controls.append(select);
    } else controls.append(badge('Подтверждённый IOC','bad'));
    controls.append(el('button',{class:'danger',onclick:runAction(async()=>{
      rememberChange(await api('/knowledge/entries/'+kbKind+'/'+row.id,{method:'DELETE'}));
      await loadKnowledge(); notice('Запись удалена. Доступна отмена изменения.');
    })},'Удалить'));
    const content=el('div',{class:'entry-details'},'Загрузка...');
    const info=details('Посмотреть запись',content);
    let loaded=false;
    info.addEventListener('toggle',runAction(async()=>{
      if (!info.open || loaded) return;
      const entry=await api('/knowledge/entries/'+kbKind+'/'+row.id);
      content.replaceChildren(jsonBlock(entry));
      if (entry.report_id) content.prepend(el('button',{onclick:runAction(()=>openReport(entry.report_id))},'Открыть исходную проверку'));
      loaded=true;
    }));
    return [descriptor,source,controls,info];
  });
  $('kb-list').replaceChildren(rows.length?table(['Объект','Происхождение','Метка и действия','Данные'],rows):el('p',{class:'empty'},'По этому запросу записей нет.'));
  $('kb-prev').disabled=kbOffset===0; $('kb-next').disabled=kbOffset+30>=kbTotal;
  $('kb-range').textContent=kbTotal?'Записи '+(kbOffset+1)+'-'+Math.min(kbOffset+30,kbTotal)+' из '+kbTotal:'0 записей';
}
for (const button of document.querySelectorAll('[data-kb-kind]')) button.addEventListener('click',runAction(async()=>{
  kbKind=button.dataset.kbKind; kbOffset=0; $('kb-query').value=''; await loadEntries();
}));
$('kb-search-form').addEventListener('submit',runAction(async event=>{event.preventDefault();kbOffset=0;await loadEntries();}));
$('kb-prev').addEventListener('click',runAction(async()=>{kbOffset=Math.max(0,kbOffset-30);await loadEntries();}));
$('kb-next').addEventListener('click',runAction(async()=>{kbOffset+=30;await loadEntries();}));
$('kb-undo').addEventListener('click',runAction(async()=>{
  const last=kbChanges[kbChanges.length-1]; if (!last) return;
  await api('/knowledge/undo/'+last,{method:'POST'}); kbChanges.pop(); $('kb-undo').hidden=!kbChanges.length;
  await loadKnowledge(); notice('Последнее изменение отменено.');
}));
$('kb-add-form').addEventListener('submit',runAction(async event=>{
  event.preventDefault();
  await api('/knowledge/entries/'+kbKind,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({value:$('kb-add-value').value.trim(),source:$('kb-add-source').value.trim()})});
  $('kb-add-value').value='';kbOffset=0;await loadKnowledge();notice('Подтверждённый индикатор добавлен.');
}));
$('kb-import-form').addEventListener('submit',runAction(async event=>{
  event.preventDefault();
  const file=$('kb-import-file').files[0];if (!file) throw new Error('Выберите файл.');
  const button=event.target.querySelector('button');button.disabled=true;
  try {
    const form=new FormData();form.append('file',file);form.append('label',$('kb-import-label').value);form.append('comment',$('kb-import-comment').value);form.append('learn_forms',String($('kb-import-forms').checked));
    const result=await api('/knowledge/import-file',{method:'POST',body:form});
    $('kb-import-status').replaceChildren(' Образец добавлен. ',el('button',{type:'button',class:'link-button',onclick:runAction(()=>openReport(result.report_id))},'Открыть проверку'));
    await loadKnowledge();
  } finally {button.disabled=false;}
}));
const initialReport=new URLSearchParams(location.search).get('report');
if (initialReport && /^[0-9a-f]{32}$/.test(initialReport)) runAction(()=>openReport(initialReport))();

