"""Browse/edit the existing knowledge tables; every mutation has a local undo."""
import json,re,sqlite3,uuid
from contextlib import closing
from pathlib import Path
from .kb import initialize_empty_kb
from .templates import SCHEMA as TEMPLATE_SCHEMA
TABLES={'hashes':'known_hashes','templates':'behavior_templates','iocs':'url_iocs'}
AUDIT='''CREATE TABLE IF NOT EXISTS knowledge_changes(id TEXT PRIMARY KEY,kind TEXT NOT NULL,before_json TEXT NOT NULL,after_json TEXT,undone INTEGER NOT NULL DEFAULT 0)'''
def connection(path):
 if not Path(path).exists(): initialize_empty_kb(Path(path))
 con=sqlite3.connect(path,timeout=30); con.row_factory=sqlite3.Row
 con.executescript(TEMPLATE_SCHEMA+';'+AUDIT)
 return con
def browse(path,kind,query='',offset=0,limit=50):
 if kind not in TABLES: raise ValueError('Unknown knowledge collection')
 with closing(connection(path)) as con:
  table=TABLES[kind]
  columns=[r[1] for r in con.execute('PRAGMA table_info('+table+')')]
  clause=' WHERE '+' OR '.join('CAST('+c+' AS TEXT) LIKE ?' for c in columns) if query else ''
  args=['%'+query[:200]+'%']*len(columns) if query else []
  total=con.execute('SELECT count(*) FROM '+table+clause,args).fetchone()[0]
  rows=[dict(r) for r in con.execute('SELECT rowid AS id,* FROM '+table+clause+' ORDER BY rowid DESC LIMIT ? OFFSET ?',[*args,min(100,max(1,limit)),max(0,offset)])]
 return {'kind':kind,'total':total,'offset':max(0,offset),'rows':rows}

def inspect_entry(path,kind,identifier):
 if kind not in TABLES: raise ValueError('Unknown knowledge collection')
 with closing(connection(path)) as con:
  row=con.execute('SELECT rowid AS id,* FROM '+TABLES[kind]+' WHERE rowid=?',(identifier,)).fetchone()
  if not row: raise LookupError('Entry not found')
  result=dict(row)
  if kind=='hashes':
   result['fingerprints']=[dict(r) for r in con.execute('SELECT source_id,features_json,label FROM fingerprints WHERE sha256=? LIMIT 5',(row['sha256'],))]
   for feature in result['fingerprints']:
    try:feature['features_json']=json.loads(feature['features_json'])
    except (ValueError,TypeError):pass
  if kind=='templates' and row['source_id'].startswith('review:'):
   try:
    review=con.execute('SELECT report_id,name,comment FROM reviewed_samples WHERE id=?',(row['source_id'].split(':')[1],)).fetchone()
    if review:result.update(dict(review))
   except sqlite3.OperationalError:pass
  result['material_note']='Архивная запись хранит отпечатки и происхождение, а не полный исходный файл. Новые письма и выбранные формы сохраняются в истории вместе с материалами.'
 return result
def mutate(path,kind,identifier,*,label=None,delete=False):
 if kind not in TABLES: raise ValueError('Unknown knowledge collection')
 table=TABLES[kind]
 with closing(connection(path)) as con,con:
  row=con.execute('SELECT rowid AS _rowid,* FROM '+table+' WHERE rowid=?',(identifier,)).fetchone()
  if not row: raise LookupError('Entry not found')
  before=dict(row); before.pop('_rowid')
  change=uuid.uuid4().hex
  if delete:
   con.execute('DELETE FROM '+table+' WHERE rowid=?',(identifier,)); after=None
  elif kind=='templates' and label in {'phishing','benign','unreviewed'}:
   con.execute('UPDATE '+table+' SET label=?,provenance=? WHERE rowid=?',('provider-phishing-unreviewed' if label=='unreviewed' else label,'user-reviewed-knowledge',identifier))
   after=dict(con.execute('SELECT * FROM '+table+' WHERE rowid=?',(identifier,)).fetchone())
  elif kind=='hashes' and label in {'phishing','benign','unreviewed'}:
   con.execute('UPDATE '+table+' SET verdict=?,provenance=? WHERE rowid=?',('BENIGN' if label=='benign' else 'PHISHING','provider-labelled-phishing-sample' if label=='unreviewed' else 'user-confirmed' if label=='phishing' else 'user-reviewed-benign',identifier))
   after=dict(con.execute('SELECT * FROM '+table+' WHERE rowid=?',(identifier,)).fetchone())
  else: raise ValueError('Unsupported label or collection')
  con.execute('INSERT INTO knowledge_changes VALUES(?,?,?,?,0)',(change,kind,json.dumps(before),json.dumps(after) if after else None))
 return {'change_id':change,'deleted':delete}
def undo(path,identifier):
 with closing(connection(path)) as con,con:
  change=con.execute('SELECT * FROM knowledge_changes WHERE id=? AND undone=0',(identifier,)).fetchone()
  if not change: raise LookupError('Change not found')
  table=TABLES[change['kind']]; row=json.loads(change['before_json']); after=json.loads(change['after_json']) if change['after_json'] else None
  keys=['sha256','source_id'] if change['kind']=='templates' else ['sha256'] if change['kind']=='hashes' else ['value']
  clause=' AND '.join(k+'=?' for k in keys); values=[row[k] for k in keys]
  existing=con.execute('SELECT * FROM '+table+' WHERE '+clause,values).fetchone()
  if existing and (after is None or dict(existing)!=after): raise ValueError('Entry changed again; undo would overwrite newer work')
  if existing: con.execute('DELETE FROM '+table+' WHERE '+clause,values)
  columns=list(row)
  con.execute('INSERT INTO '+table+'('+','.join(columns)+') VALUES('+','.join('?' for _ in columns)+')',[row[c] for c in columns])
  con.execute('UPDATE knowledge_changes SET undone=1 WHERE id=?',(identifier,))
 return {'restored':True}
def add_indicator(path,kind,value,source='Добавлено вручную',object_type='file'):
 from .urltools import normalize_url,ioc_url_key
 if kind=='hashes':
  value=value.strip().lower()
  if not re.fullmatch('[0-9a-f]{64}',value): raise ValueError('SHA256 must contain 64 hexadecimal digits')
  with closing(connection(path)) as con,con:
   con.execute('INSERT INTO known_hashes VALUES(?,?,?,?,?,?,?)',(value,object_type[:40],'PHISHING',source[:1000],None,None,'user-confirmed'))
 elif kind=='iocs':
  value=ioc_url_key(value)
  with closing(connection(path)) as con,con:
   con.execute('INSERT INTO url_iocs VALUES(?,?,?,?,?)',(value,'url','PHISHING',source[:1000],None))
 else: raise ValueError('Use file review to add a page template')
 return {'added':True}

