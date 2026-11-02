'use strict';
const visualRoleNames={'mail-render':'Письмо','local-render':'Страница HTML',screenshot:'Снимок сайта','pdf-render':'Страница PDF','logo-asset':'Картинка','embedded-logo':'Картинка','source-image':'Изображение','logo-crop':'Область'};
function scoreRows(m) {
  const s=m.scores || {};
  return [['Фишинг / мошенничество',s.phishing ?? s.fraud],['Легитимное',s.legitimate ?? s.benign],['Спам / реклама',s.spam ?? s.marketing]].filter(([,v])=>Number.isFinite(v)).map(([n,v])=>[n,v.toFixed(3)]);
}
function visualWords(m) {
  const values=[...(m.text_matches || []),...(m.ocr_wordmarks || []),...(m.brand_candidates || []).filter(c=>c.method?.startsWith('ocr-'))];
  return [...new Map(values.map(c=>[[c.brand,c.text,(c.roi || []).join(',')].join('|'),c])).values()];
}
function visualGraphics(m) {return m.graphic_matches || (m.brand_candidates || []).filter(c=>!c.method?.startsWith('ocr-'));}
function visualUseful(m) {return visualGraphics(m).length || visualWords(m).length || m.ocr_text?.trim();}
function visualCard(wrapper,views) {
  const order={'mail-render':0,screenshot:1,'local-render':2,'pdf-render':3,'source-image':4,'logo-asset':5,'embedded-logo':5,'logo-crop':6};
  views=[...views].sort((a,b)=>(order[a.image_context?.image_role] ?? 8)-(order[b.image_context?.image_role] ?? 8));
  const first=views[0],ctx=first.image_context || {},found=new Map();
  const card=el('section',{class:'model-card visual-card'},[el('h3',{},'Изображения и OCR'),el('div',{class:'small muted url-text'},ctx.url || ctx.title || 'Входной файл')]);
  for (const v of views) {
    for (const c of visualGraphics(v)) found.set('image:'+c.brand,[badge('Логотип'),c.brand,{'sift-ransac':'Геометрия и локальные признаки','localized-pixel-shape':'Силуэт и цвета','exact-reference-pixels':'Точное изображение'}[c.method] || c.method]);
    for (const c of visualWords(v)) found.set('ocr:'+c.brand+':'+c.text,[badge('OCR'),c.brand,'«'+(c.text || c.brand)+'»']);
  }
  if (found.size) card.append(table(['Признак','Сервис / организация','Найдено'],[...found.values()]));
  else if (!views.some(v=>v.ocr_text)) card.append(el('p',{class:'small muted'},'Совпадений логотипа или названия не найдено.'));
  const text=[...new Set(views.map(v=>v.ocr_text).filter(Boolean))].sort((a,b)=>b.length-a.length)[0];
  if (text) card.append(details('Распознанный текст',el('pre',{class:'source-text'},text)));
  const preview=el('div'),tabs=el('div',{class:'view-tabs'});
  function select(v,button) {
    for (const b of tabs.querySelectorAll('button')) b.classList.toggle('active',b===button);
    preview.replaceChildren(imageProof(wrapper,v.image_context,{...v,brand_candidates:[...visualGraphics(v),...visualWords(v)]}));
  }
  if (wrapper.report_id && first.image_context?.artifact_id) {
    for (const v of views) {const button=el('button',{type:'button',onclick:()=>select(v,button)},visualRoleNames[v.image_context?.image_role] || 'Изображение');tabs.append(button);}
    if (views.length>1) card.append(tabs);
    select(first,tabs.querySelector('button'));card.append(preview);
  }
  const missing=Math.max(...views.map(v=>v.missing_images || 0));
  if (missing) card.append(el('p',{class:'small warning'},'Не загрузилось картинок: '+missing));
  card.append(details('Технические данные',jsonBlock(views)));return card;
}
function textModelCard(wrapper,m) {
  const name=m.model==='Laya multilingual'?'Laya':m.model.includes('phishing-scam-detector')?'Horizon':m.model.includes('Qwen')?'Qwen':m.model;
  const card=el('section',{class:'model-card'},[el('h3',{},name)]);
  if (m.affects_verdict) card.append(badge('Учтено в вердикте','warn'));
  if (m.scores) {
    card.append(table(['Класс','Оценка'],scoreRows(m)));
    if (m.evidence_text) {
      const caption=(m.evidence_is_full_text || m.windows===1 && !m.coverage_limited)?'Проверенный текст':'Проверенный фрагмент '+((m.selected_window || 0)+1)+' из '+(m.windows || 1);
      card.append(details(caption,el('pre',{class:'source-text'},m.evidence_text)));
    }
    if (m.coverage_limited) card.append(el('p',{class:'small warning'},'Длинный текст проверен выборочно.'));
  } else {
    const facts=m.structured_extract;
    if (facts) {
      if (m.validation_notes?.length) card.append(el('p',{class:'small warning'},'Объяснение не прошло проверку по источнику.'));
      else if (facts.rationale) card.append(el('p',{class:'model-comment'},facts.rationale));
      for (const q of m.evidence_quotes || (facts.evidence_spans || []).map(text=>({text}))) card.append(el('blockquote',{class:'model-quote'},[el('p',{},q.text),q.source_label?el('cite',{class:'small muted'},q.source_label):null]));
    } else if (m.parse_status==='INVALID_JSON') card.append(el('p',{class:'small warning'},'Не удалось разобрать ответ модели.'));
    else if (['NO_TEXT','UNAVAILABLE','FAILED'].includes(m.status)) card.append(el('p',{class:'small warning'},m.note || 'Модель не выполнила проверку.'));
    else if (m.brand_candidates?.length) card.append(table(['Вариант','Сходство'],m.brand_candidates.map(c=>[c.brand,String(c.cosine ?? c.score)])));
    else if (m.status==='NO_IMAGE') card.append(el('p',{class:'small muted'},'Нет изображения для проверки.'));
  }
  card.append(details('Технические данные',jsonBlock(m)));return card;
}
function buildModelCards(wrapper) {
  const main=el('div',{class:'model-grid'}),groups=new Map(),quiet=[];
  for (const m of wrapper.report.model_evidence || []) {
    if (m.model!=='Local-logo-geometry') {main.append(textModelCard(wrapper,m));continue;}
    const key=m.image_context?.scope_id || m.image_context?.artifact_id || String(groups.size);
    if (!groups.has(key)) groups.set(key,[]);groups.get(key).push(m);
  }
  for (const views of groups.values()) {if (views.some(visualUseful)) main.append(visualCard(wrapper,views));else quiet.push(views);}
  const result=el('div',{},main);
  if (quiet.length) result.append(details('Изображения без найденных признаков ('+quiet.length+')',el('div',{class:'model-grid'},quiet.map(v=>visualCard(wrapper,v)))));
  return result;
}
