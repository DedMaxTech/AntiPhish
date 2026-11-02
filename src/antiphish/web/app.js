'use strict';
const $ = id => document.getElementById(id);
let current = null, busy = false;
function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2), value);
    else if (key === 'class') node.className = value;
    else if (value !== null && value !== undefined && value !== false) node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of [children].flat(Infinity)) if (child !== null && child !== undefined) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return node;
}
function notice(text, error = false) { $('notice').hidden = !text; $('notice').textContent = text; $('notice').className = 'notice' + (error ? ' error' : ''); }
async function api(path, options = {}) {
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail || response.status));
  return data;
}
function runAction(action) { return async (...args) => { try { await action(...args); } catch (error) { notice(error.message, true); } }; }
function badge(text, type = 'neutral') { return el('span', {class:'badge '+type}, text); }
const verdictNames = {PHISHING:'Фишинг подтверждён', SUSPICIOUS:'Требует проверки', NOT_DETECTED:'Признаки фишинга не найдены'};
const statusNames = {COMPLETE:'Проверка завершена', PARTIAL:'Проверка неполная', FAILED:'Анализ не выполнен'};
function verdictBadge(report) {
  const failed = report.analysis_status === 'FAILED';
  const type = failed ? 'neutral' : report.verdict === 'PHISHING' ? 'bad' : report.verdict === 'SUSPICIOUS' ? 'warn' : report.analysis_status === 'COMPLETE' ? 'good' : 'neutral';
  return badge(failed ? 'Ошибка анализа' : report.verdict, type);
}
function table(headers, rows) {
  return el('div', {class:'table-wrap'}, el('table', {}, [
    el('thead', {}, el('tr', {}, headers.map(x => el('th', {}, x)))),
    el('tbody', {}, rows.map(row => el('tr', {}, row.map(x => el('td', {}, x)))))
  ]));
}
function details(title, content, open = false) { return el('details', open ? {open:true} : {}, [el('summary', {}, title), content]); }
function jsonBlock(value) { return el('pre', {}, JSON.stringify(value, null, 2)); }
function definitions(items) { return el('dl', {}, items.filter(([,v]) => v !== undefined && v !== null && v !== '').map(([key,value]) => [el('dt', {}, key), el('dd', {}, Array.isArray(value) ? value.join(', ') : value)])); }
function download(value, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value,null,2)], {type:'application/json'}));
  const anchor = el('a', {href:url,download:filename}); anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function showView(name) {
  for (const value of ['analysis','history','knowledge']) $('view-'+value).hidden = name !== value;
  for (const button of document.querySelectorAll('nav button')) button.classList.toggle('active', button.dataset.view === name);
}
async function openReport(identifier) {
  const data = await api('/reports/'+encodeURIComponent(identifier));
  showView('analysis'); $('batch-result').replaceChildren(); renderReport(data);
  $('result').scrollIntoView({behavior:'auto',block:'start'});
}
function highlighted(text, matches = []) {
  const box=el('div',{class:'text-preview'});
  const words=[...new Set(matches.map(x=>x.text).filter(Boolean))].sort((a,b)=>b.length-a.length);
  const clean=String(text || '').replace(/\n{3,}/g,'\n\n');
  if (!words.length) { box.textContent=clean; return box; }
  const escape=x=>[...x].map(c=>'\\^$.*+?()[]{}|'.includes(c)?'\\'+c:c).join('');
  const pattern=new RegExp(words.map(escape).join('|'),'giu');
  let position=0,match;
  while ((match=pattern.exec(clean))) {
    box.append(document.createTextNode(clean.slice(position,match.index)),el('mark',{},match[0]));
    position=match.index+match[0].length;
    if (!match[0].length) break;
  }
  box.append(document.createTextNode(clean.slice(position))); return box;
}
function textPanel(text, context, wrapper, scope='message') {
  const node=el('div',{},highlighted(text,context.highlights || []));
  if (context.text_truncated) node.append(el('p',{class:'small muted'},'Выдержка из источника.'));
  if (context.text_truncated && wrapper.report_id) node.append(el('button',{class:'small',onclick:runAction(async()=>{
    const value=await api('/reports/'+wrapper.report_id+'/text?scope='+encodeURIComponent(scope));
    if (!value.available) { notice('В старом отчёте полный текст не сохранён. Повторите проверку.'); return; }
    node.replaceChildren(highlighted(value.text,context.highlights || []));
  })},'Показать полный извлечённый текст'));
  return node;
}
function finding(item, wrapper) {
  const context=item.context || {}, body=el('div',{class:'finding-body'});
  if (context.explanation && !item.details?.identity_comparison) body.append(el('p',{class:'condition'},context.explanation));
  const identity=item.details?.identity_comparison;
  if (identity) body.append(el('div',{class:'identity-comparison'},[
    definitions([['Заявленный бренд',identity.claimed_brand],['Домен отправителя',identity.sender_domain || 'Не установлен'],['Домен ссылки действия',identity.action_hosts],['Известные домены бренда',identity.official_domains]]),
    el('p',{class:'small muted'},'Известные домены не покрывают всех партнёров бренда.')
  ]));
  if (context.highlights?.length) {
    const labels={'secret-request':'Запрос секрета',reward:'Вознаграждение',cta:'Побуждение к действию',threat:'Угроза блокировки',brand:'Название бренда',recipient:'Получатель данных',payment:'Оплата'};
    body.append(el('div',{class:'trigger-list'},[...new Set(context.highlights.map(x=>x.role).filter(Boolean))].map(x=>badge(labels[x] || 'Признак'))));
  }
  if (context.text_excerpt) body.append(details(context.selection==='exact-text'?'Фрагменты, вызвавшие правило':context.selection==='exact-headers'?'Заголовки, вызвавшие правило':'Контекст источника',textPanel(context.text_excerpt,context,wrapper,context.scope_id && context.scope_id!=='message'?context.scope_id:'message'),context.selection==='exact-text' || context.selection==='exact-headers'));
  if (context.destinations?.length) body.append(el('div',{class:'destinations'},[el('strong',{},'Ссылки действия'),...context.destinations.map(url=>el('div',{class:'url-text'},url))]));
  const rows=[['Источник',context.source_url || (context.source==='message'?(wrapper.report.input?.detected_type==='eml'?'Исходное письмо':'Исходный файл'):context.title || context.source)],['Бренд',item.details?.brand],['Форма',context.selector],['Получатель',context.destination],['Поля',context.sensitive_types],['Индикатор',context.indicator],['Вложение',context.attachment]];
  body.append(definitions(rows));
  if (context.code_excerpt) body.append(details(context.kind==='document'?'Действия документа':context.code_selection==='matched-script'?'Фрагмент скрипта, вызвавший правило':context.selection==='exact-form'?'Код формы  /  значения скрыты':'Код страницы  /  контекст',el('pre',{},context.code_excerpt),true));
  if (context.image_artifact && wrapper.report_id && (wrapper.artifacts || []).some(a=>a.id===context.image_artifact && a.kind==='image')) {
    const url='/reports/'+wrapper.report_id+'/artifacts/'+context.image_artifact;
    body.append(details(context.image_label || 'Изображение',el('a',{href:url,target:'_blank',rel:'noopener'},el('img',{src:url,class:'screenshot',alt:'Изображение источника',loading:'lazy'}))));
  }
  body.append(details('Технические детали',jsonBlock({source_sha256:context.source_sha256,attachment_sha256:context.attachment_sha256,...item.details})));
  const role=context.policy_role;
  return el('details',{class:'finding',...(role==='proof' || role==='alert'?{open:true}:{})},[
    el('summary',{},[badge(role==='proof'?'Доказательство':role==='alert'?'Предупреждение':'Наблюдение',role==='proof'?'bad':role==='alert'?'warn':'neutral'),el('span',{},[el('span',{class:'reason-summary'},item.summary),el('span',{class:'finding-code'},item.code+(context.source_url?'  /  '+new URL(context.source_url).hostname:''))])]),body]);
}
function groupedReasons(reasons) {
  const groups=new Map();
  for (const item of reasons) {
    const key=JSON.stringify([item.code,item.scope_id,item.details?.form_id,item.details?.form_index,item.details?.destinations || item.details?.destination || item.details?.url]);
    if (groups.has(key) && item.independent_group==='message-scenario') {
      const first=groups.get(key);
      first.details={...first.details,combined_brands:[...new Set([...(first.details.combined_brands || [first.details.brand]),item.details.brand].filter(Boolean))],related_findings:(first.details.related_findings || 1)+1};
    } else groups.set(key,structuredClone(item));
  }
  return [...groups.values()];
}
function routeTable(report) {
  const pageById=new Map((report.pages || []).map(p=>[p.id,p]));
  function source(value) {
    if (!value || value==='input') return 'Письмо / входной объект';
    const page=pageById.get(value);
    return page ? el('div',{},[el('strong',{},page.title || 'Страница'),el('div',{class:'url-text small'},page.url || 'HTML в исходном письме')]) : value.startsWith('page:')?'Страница из цепочки':value;
  }
  const rows=(report.routes || []).map((r,i)=>{
    const target=pageById.get(r.to), url=r.url || target?.url || r.to;
    const outcome=r.kind==='failed-navigation'?badge(r.http_status?'HTTP '+r.http_status:'Не загружено','warn'):r.kind==='decoded-wrapper'?badge('Адрес раскрыт'):badge('Загружено','good');
    return [i+1,source(r.from),el('div',{},[r.reason?el('div',{class:'small muted'},r.reason):null,el('div',{class:'url-text'},r.via || url),url && url!==r.via?el('div',{class:'url-text small'},'Открыт: '+url):null,target?.title?el('div',{class:'small muted'},target.title):null,r.redirect_chain?.length>1?details('Цепочка адресов',el('ol',{},r.redirect_chain.map(x=>el('li',{class:'url-text'},x)))):null]),el('div',{},[outcome,r.error?el('p',{class:'small'},r.error):null])];
  });
  return table(['Шаг','Источник','Ссылка / полученная страница','Результат'],rows);
}
function imageProof(wrapper,image,model) {
  const figure=el('div',{class:'image-proof'},el('img',{src:'/reports/'+wrapper.report_id+'/artifacts/'+image.artifact_id,alt:'Изображение для проверки бренда',loading:'lazy'}));
  const [width,height]=model.image_size || [];
  if (width>0 && height>0) for (const candidate of (model.brand_candidates || []).slice(0,5)) {
    const [x1,y1,x2,y2]=candidate.roi || [];
    if (![x1,y1,x2,y2].every(Number.isFinite) || x2<=x1 || y2<=y1) continue;
    const ocr=candidate.method?.startsWith('ocr-');
    const box=el('span',{class:'brand-box'+(ocr?' ocr':''),title:candidate.brand},el('span',{},candidate.brand+(ocr?' (OCR)':'')));
    Object.assign(box.style,{left:(100*x1/width)+'%',top:(100*y1/height)+'%',width:(100*(x2-x1)/width)+'%',height:(100*(y2-y1)/height)+'%'});
    figure.append(box);
  }
  return el('div',{class:'image-proof-scroll'},figure);
}
function modelCards(wrapper) { return buildModelCards(wrapper); }
function reviewPanel(wrapper) {
  const report = wrapper.report;
  const panel = el('section',{class:'panel'},[el('h2',{},'Добавить в образцы'),
    el('p',{class:'small muted'},'Метка будет учтена при следующей проверке.')]);
  const pages = (report.pages || []).filter(p => p.identity_source === 'dom' && p.forms?.length);
  if (pages.length) {
    const choices = el('div');
    for (const page of pages) choices.append(el('label',{class:'check page-option'},[
      el('input',{type:'checkbox','data-learning-page':page.id}),
      'Эталон страницы с формой: '+(page.url || page.title || page.id)
    ]));
    panel.append(details('Дополнительно: добавить эталоны страниц ('+pages.length+')',choices));
  }
  const comment = el('textarea',{placeholder:'Почему образец фишинговый или легитимный (необязательно)',maxlength:'2000','aria-label':'Комментарий к образцу'});
  const note = el('p',{class:'review-note','aria-live':'polite'});
  const buttons = el('div',{class:'review-buttons'});
  let savedReview = null;
  const save = label => runAction(async () => {
    for (const button of buttons.querySelectorAll('button')) button.disabled = true;
    try {
      const pageIds = [...panel.querySelectorAll('[data-learning-page]:checked')].map(input => input.dataset.learningPage);
      savedReview = await api('/reviews',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({report_id:wrapper.report_id,label,comment:comment.value,page_ids:pageIds})});
      note.textContent = 'Сохранено: '+(label === 'phishing' ? 'фишинговый' : 'легитимный')+' образец. Эталонов страниц: '+savedReview.selected_pages+'.'+(savedReview.ignored_pages?' Часть страниц не сохранена.':'');
      undo.hidden = false;
    } finally { for (const button of buttons.querySelectorAll('button')) button.disabled = false; }
  });
  const undo = el('button',{type:'button',hidden:true,onclick:runAction(async () => {
    if (!savedReview) return;
    await api('/reviews/'+savedReview.id,{method:'DELETE'}); savedReview = null; undo.hidden = true; note.textContent = 'Метка и связанные шаблоны удалены.';
  })},'Отменить метку');
  buttons.append(el('button',{type:'button',onclick:save('phishing')},'Фишинговое'),el('button',{type:'button',onclick:save('benign')},'Легитимное'),undo);
  panel.append(comment,buttons,note);
  return panel;
}
function renderReport(wrapper) {
  current = wrapper;
  const report = wrapper.report, container = $('result'); container.replaceChildren();
  const failed = report.analysis_status === 'FAILED';
  const summary = el('section',{class:'panel result-summary','data-verdict':report.verdict},[
    el('div',{class:'summary-head'},[el('h2',{},failed ? 'Анализ не выполнен' : verdictNames[report.verdict] || report.verdict),verdictBadge(report)]),
    el('div',{class:'summary-meta'},[
      el('span',{},statusNames[report.analysis_status] || report.analysis_status),
      el('span',{},report.input?.name || report.input?.value || 'Объект'),
      el('span',{},(report.configuration?.profile || '')+' / '+(report.configuration?.network_mode || '')),
      el('span',{},((report.timings_ms?.total || 0)/1000).toFixed(2)+' с')
    ])
  ]);
  if (report.analysis_status !== 'COMPLETE') summary.append(el('p',{class:'summary-text muted'},'Не все данные доступны.'));
  if (!report.configuration?.components) summary.append(el('p',{class:'small warning'},'Старый формат отчёта. Для полного контекста повторите проверку.'));
  if (report.configuration?.decision?.ai_based) summary.append(el('p',{class:'ai-decision'},'Требует проверки по оценке ИИ'));
  const actions = el('div',{class:'actions'},el('button',{type:'button',onclick:() => download(wrapper,'antiphish-report.json')},'Скачать JSON'));
  const original = (wrapper.artifacts || []).find(a => a.kind === 'original');
  if (original && wrapper.report_id) actions.append(el('a',{href:'/reports/'+wrapper.report_id+'/artifacts/'+original.id,download:original.name},'Скачать исходник'));
  if (wrapper.report_id && !wrapper.urls_revealed) actions.append(el('button',{onclick:runAction(async()=>{
    const data=await api('/reports/'+wrapper.report_id+'/raw-urls');
    if (!data.urls.length) { notice('Полные адреса не сохранены в старом отчёте. Повторите проверку.'); return; }
    const mapping=new Map(data.urls.flatMap(x=>[[x.display,x.full],[x.context_display,x.full]]).filter(x=>x[0]));
    function reveal(value) { return typeof value==='string'?(mapping.get(value) || value):Array.isArray(value)?value.map(reveal):value && typeof value==='object'?Object.fromEntries(Object.entries(value).map(([k,v])=>[k,reveal(v)])):value; }
    wrapper={...wrapper,report:reveal(wrapper.report),urls_revealed:true}; renderReport(wrapper);
    notice('Показаны полные URL.');
  })},'Показать полные URL'));
  if (original && wrapper.report_id) actions.append(el('button',{onclick:runAction(async()=>{
    const response=await fetch('/reports/'+wrapper.report_id+'/artifacts/'+original.id);
    const transfer=new DataTransfer(); transfer.items.add(new File([await response.blob()],original.name));
    $('file').files=transfer.files; $('source').value=''; $('batch-mode').checked=false;
    $('analysis-form').requestSubmit(); $('analysis-form').scrollIntoView({block:'start'});
  })},'Перепроверить с текущими настройками'));
  summary.append(actions); container.append(summary);
  const message = report.message || {};
  if (message.subject || message.from || message.text_excerpt) container.append(details('Письмо и извлечённый текст',el('section',{class:'panel'},[
    definitions([['Тема',message.subject],['Отправитель',message.from],['Кому',message.to],['Ответить',message['reply-to']]]),
    textPanel(message.text_excerpt || 'Текст не извлечён',message,wrapper)
  ])));
  const reasons = groupedReasons(report.reason_codes || []), alerts = reasons.filter(r => ['proof','alert'].includes(r.context?.policy_role));
  if (alerts.length) {container.append(el('h2',{},'Основания результата'));for (const item of alerts) container.append(finding(item,wrapper));}
  const observations = reasons.filter(r => !alerts.includes(r));
  if (observations.length) container.append(details('Другие наблюдения ('+observations.length+')',el('div',{},observations.map(item => finding(item,wrapper)))));
  const warnings = [...(report.warnings || []),...(report.network_warnings || []),...(report.model_warnings || [])];
  if (warnings.length) container.append(details('Ограничения проверки ('+warnings.length+')',el('ul',{},warnings.map(w => el('li',{},w))),true));
  if (report.routes?.length) container.append(details('Переходы по ссылкам ('+report.routes.length+')',routeTable(report),true));
  if (report.urls?.length) {
    const states={DECODED:'Адрес раскрыт',NOT_NAVIGATED:'Служебный URL или ресурс',SKIPPED_ACTION:'Действие пропущено',FETCHED:'Загружен',PARTIAL:'Загружен частично',FAILED:'Ошибка загрузки'};
    container.append(details('Все извлечённые URL ('+report.urls.length+')',table(['Адрес','Назначение','Загрузка'],report.urls.slice(0,100).map(u=>[el('div',{class:'url-text'},u.original),u.selection_reason || u.source || '',states[u.fetch_status] || 'Не посещался']))));
  }
  const checks=(report.configuration?.brand_checks || []).filter(c=>c.page || c.form_id);
  if (checks.length) {
    const names={verified:'Домен и получатель подтверждены',foreign_secret_collector:'Секрет запрашивается вне доменов бренда',external_collector:'Внешний получатель секрета',unverified:'Принадлежность не подтверждена',partner_context:'Упоминание на официальной странице',provider_context:'Платформа формы',partial:'Проверка неполная'};
    container.append(details('Сервис и получатель данных ('+checks.length+')',table(['Заявленный сервис','Страница','Получатель','Результат'],checks.map(c=>[
      el('div',{},[el('strong',{},c.brand),el('div',{class:'small muted'},c.sources.map(s=>({'ocr-header-wordmark':'OCR названия',DOM:'HTML',OCR:'OCR', 'exact-reference-pixels':'Точный эталон','sift-ransac':'Локальные признаки','localized-pixel-shape':'Форма и цвет'}[s] || s)).join(', '))]),
      el('span',{class:'url-text'},c.page || 'Локальный файл'),el('span',{class:'url-text'},c.destination || 'Форма не найдена'),
      badge(names[c.status] || c.status,['foreign_secret_collector','external_collector'].includes(c.status)?'warn':c.status==='verified'?'good':'neutral')])) ,true));
  }
  if (report.attachments?.length) container.append(details('Вложения ('+report.attachments.length+')',table(['Файл','Тип','Размер','Разбор'],report.attachments.map(a => [a.name,a.media_type,(a.size/1024).toFixed(1)+' КиБ',a.status]))));
  if (report.model_evidence?.length) container.append(details('Анализ текста и изображений',modelCards(wrapper),true));
  container.append(details('Время этапов и конфигурация',jsonBlock({timings_ms:report.timings_ms,configuration:report.configuration})));
  if (wrapper.report_id && !failed) container.append(reviewPanel(wrapper));
}
function renderBatch(data) {
  current = data; $('result').replaceChildren(); $('batch-result').replaceChildren();
  const stats = data.statistics || {};
  $('batch-result').append(el('section',{class:'panel'},[
    el('div',{class:'summary-head'},[el('h2',{},'Пакет обработан'),badge(data.batch_status || 'COMPLETE')]),
    el('p',{},'Объектов: '+(stats.items || 0)+'  /  Время: '+(stats.elapsed_seconds || 0).toFixed(2)+' с  /  Повторные копии: '+(stats.duplicates_reused || 0)),
    el('button',{onclick:() => download(data,'antiphish-batch.json')},'Скачать все результаты')
  ]));
  const rows = (data.results || []).slice(0,500).map(row => [row.source,verdictBadge(row.report),statusNames[row.report.analysis_status] || row.report.analysis_status,el('button',{onclick:runAction(async () => row.report_id ? openReport(row.report_id) : renderReport({report:row.report}))},'Открыть')]);
  $('batch-result').append(table(['Объект','Вердикт','Полнота','Результат'],rows));
  if ((data.results || []).length > 500) $('batch-result').append(el('p',{class:'muted'},'Показаны первые 500 объектов. Полный список доступен в JSON.'));
  if (data.warnings?.length) $('batch-result').append(details('Ограничения пакета',jsonBlock(data.warnings),true));
}
async function loadHistory() {
  const data = await api('/reports?limit=100');
  $('history-list').replaceChildren(data.reports.length ? table(['Объект','Вердикт','Полнота','Проверка'],data.reports.map(row => [
    row.source_id || row.report_id,verdictBadge(row),statusNames[row.analysis_status] || row.analysis_status,
    el('button',{onclick:runAction(() => openReport(row.report_id))},'Открыть')
  ])) : el('p',{class:'empty'},'Пока нет сохранённых проверок.'));
}
async function loadKnowledge() {
  const [data,reviews] = await Promise.all([api('/knowledge'),api('/reviews?limit=1000')]);
  const names = {reviewed_samples:'Размечено вручную',behavior_templates:'Эталонов страниц',known_hashes:'Отпечатков файлов',url_iocs:'Ручных URL-индикаторов'};
  $('knowledge-status').replaceChildren(el('div',{class:'kpi'},Object.entries(names).map(([key,label]) => el('div',{},[el('strong',{},data.counts?.[key] || 0),el('span',{},label)]))));
  if (data.logo_gallery?.references) {
    const groups=new Map();
    for (const r of data.logo_gallery.items || []) { if (!groups.has(r.brand)) groups.set(r.brand,[]); groups.get(r.brand).push(r); }
    const cards=[...groups].sort((a,b)=>a[0].localeCompare(b[0],'ru')).map(([brand,rows])=>el('details',{class:'logo-group'},[
      el('summary',{},[el('img',{src:'/knowledge/logos/'+rows[0].sha256,alt:brand,loading:'lazy'}),el('strong',{},brand),el('span',{class:'small muted'},rows.length+' эталонов')]),
      el('div',{class:'logo-variants'},rows.map(r=>el('a',{href:r.source_url,target:'_blank',rel:'noopener noreferrer',title:'Источник: '+r.source_url},el('img',{src:'/knowledge/logos/'+r.sha256,alt:brand,loading:'lazy'}))))
    ]));
    $('knowledge-status').append(details('Галерея: '+groups.size+' брендов, '+data.logo_gallery.references+' эталонов',el('div',{class:'logo-gallery'},cards)));
  }
  const feeds = data.reputation?.sources || [];
  $('feeds').replaceChildren(feeds.length ? table(['Источник','Записей','Возраст','Состояние'],feeds.map(row => [row.provider,row.records,(row.age_hours/24).toFixed(1)+' дн.',badge(row.stale ? 'Нужно обновить' : 'Действует',row.stale ? 'warn' : 'good')])) : el('p',{class:'empty'},'Локальные списки ещё не загружены.'));
  $('samples').replaceChildren(reviews.samples.length ? table(['Образец','Метка','Комментарий','Действия'],reviews.samples.map(row => [
    row.name || row.id,badge(row.label === 'phishing' ? 'Фишинговый' : 'Легитимный',row.label === 'phishing' ? 'bad' : 'good'),row.comment || '-',
    el('div',{class:'actions'},[el('button',{onclick:runAction(() => openReport(row.report_id))},'Открыть'),
      el('button',{class:'danger',onclick:runAction(async () => { await api('/reviews/'+row.id,{method:'DELETE'}); await loadKnowledge(); notice('Метка и связанные шаблоны удалены.'); })},'Удалить метку')])
  ])) : el('p',{class:'empty'},'Размеченных образцов пока нет.'));
  await loadEntries();
}
for (const button of document.querySelectorAll('nav button')) button.addEventListener('click',runAction(async () => {
  showView(button.dataset.view); if (button.dataset.view === 'history') await loadHistory(); if (button.dataset.view === 'knowledge') await loadKnowledge();
}));
$('refresh-history').addEventListener('click',runAction(loadHistory));
$('refresh-knowledge').addEventListener('click',runAction(loadKnowledge));
$('network').addEventListener('change',() => { $('browser-confirm').hidden = $('network').value !== 'browser'; });
$('file').addEventListener('change',() => { if ($('file').files[0]) { $('source').value = ''; $('batch-mode').checked = /\.(zip|tar|tgz|tar\.gz|tar\.bz2)$/i.test($('file').files[0].name); } });
$('source').addEventListener('input',() => { if ($('source').value) $('file').value = ''; });
$('analysis-form').addEventListener('submit',async event => {
  event.preventDefault(); if (busy) return;
  try {
    const components=readComponents();
    const file = $('file').files[0], source = $('source').value.trim(), network = $('network').value, profile = $('profile').value, batch = $('batch-mode').checked;
    if (!file && !source) throw new Error('Выберите файл или укажите URL / путь.');
    if (file && file.size > 50*1024*1024) throw new Error('Файл превышает 50 МиБ.');
    if (network === 'browser' && !$('browser-risk').checked) throw new Error('Для Browser отметьте разрешение посещения сайтов.');
    busy = true; $('run').disabled = true; $('analysis-form').setAttribute('aria-busy','true'); notice(''); $('progress').textContent = 'Анализ...';
    let options, path;
    if (file) {
      const form = new FormData(); form.append('file',file); form.append('profile',profile); form.append('network',network); form.append('persist','true'); form.append('options',JSON.stringify(components));
      if (network === 'browser') form.append('confirm_browser_risk','I_UNDERSTAND');
      path = batch ? '/batch/file' : '/analyze/file'; options = {method:'POST',body:form};
    } else {
      path = batch ? '/batch' : '/analyze'; options = {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source,profile,network,persist:true,options:components,confirm_browser_risk:network === 'browser' ? 'I_UNDERSTAND' : null})};
    }
    const data = await api(path,options);
    if (batch) renderBatch(data); else { $('batch-result').replaceChildren(); renderReport(data); }
    $('progress').textContent = 'Готово'; $(batch?'batch-result':'result').scrollIntoView({behavior:'auto',block:'start'});
  } catch (error) { notice(error.message,true); $('progress').textContent = ''; }
  finally { busy = false; $('run').disabled = false; $('analysis-form').removeAttribute('aria-busy'); }
});
$('update-feeds').addEventListener('click',runAction(async () => {
  $('update-feeds').disabled = true; notice('Обновляю локальные списки. Предыдущий снимок сохраняется при ошибке источника.');
  try { const result = await api('/knowledge/update-feeds',{method:'POST'}); await loadKnowledge(); notice('Обновление завершено: '+result.status, !['OK','READY'].includes(result.status)); }
  finally { $('update-feeds').disabled = false; }
}));


const fileField=document.querySelector('.file-field');
fileField.addEventListener('dragover',event=>{event.preventDefault();fileField.classList.add('drag-over');});
fileField.addEventListener('dragleave',()=>fileField.classList.remove('drag-over'));
fileField.addEventListener('drop',event=>{event.preventDefault();fileField.classList.remove('drag-over');if(event.dataTransfer.files.length){$('file').files=event.dataTransfer.files;$('file').dispatchEvent(new Event('change'));}});
