"""Paired local text-model audit. Dataset labels are never used for training."""
import argparse
import hashlib
import json
import time
import zipfile
from pathlib import Path

from antiphish.config import DEFAULT_LIMITS
from antiphish.dataset import read_manifest, interval
from antiphish.extractors import extract_any
from antiphish.textmodel import score, REPOSITORY, REVISION


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--limit',type=int)
    args=parser.parse_args()
    if args.output.exists():parser.error('Choose a new output file')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    rows=[]; started=time.perf_counter()
    journal=args.output.with_suffix('.jsonl')
    with zipfile.ZipFile(args.archive) as z,journal.open('x',encoding='utf-8') as out:
        prefix,records=read_manifest(z)
        for record in records[:args.limit]:
            path=record.get('evaluation_path') or record['path']
            data=z.read(prefix+path)
            expected=record.get('sha256_evaluation') or record.get('sha256')
            if expected and hashlib.sha256(data).hexdigest()!=expected:raise ValueError('Input checksum mismatch')
            extracted=extract_any(data,Path(path).name,None,DEFAULT_LIMITS,quality=False)
            text=extracted.metadata.get('subject','')+'\n'+extracted.text
            result=score(text)
            row={k:record.get(k) for k in ('id','label','language','source','group_id','review_status')}
            row.update(head=result['window_scores'][0],windowed=result['scores'],windows=result['windows'],tokens=result['input_tokens'],coverage_limited=result['coverage_limited'],runtime_ms=result['runtime_ms'])
            rows.append(row);out.write(json.dumps(row,ensure_ascii=False)+'\n');out.flush()
            if len(rows)%50==0:print('Processed',len(rows),flush=True)
    summary={}
    for mode in ('head','windowed'):
        summary[mode]={}
        for threshold in (.5,.9,.95,.99):
            positives=[r for r in rows if r['label']=='phishing'];negatives=[r for r in rows if r['label']=='benign']
            tp=sum(r[mode]['fraud']>=threshold for r in positives);fp=sum(r[mode]['fraud']>=threshold for r in negatives)
            summary[mode][str(threshold)]={'tp':tp,'positives':len(positives),'fp':fp,'negatives':len(negatives),'recall':tp/len(positives) if positives else None,'fpr':fp/len(negatives) if negatives else None,'recall_wilson95':interval(tp,len(positives)),'fpr_wilson95':interval(fp,len(negatives))}
    payload={'model':REPOSITORY,'revision':REVISION,'archive_sha256':hashlib.sha256(args.archive.read_bytes()).hexdigest(),'seconds':time.perf_counter()-started,'summary':summary,'rows':rows,'limitations':['Previously inspected development dataset, not independent or zero-shot acceptance evidence','Supplied labels are not independently verified','Maximum of window scores is not a calibrated probability; all thresholds are descriptive, not selected for production']}
    args.output.write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(summary,ensure_ascii=False),flush=True)


if __name__=='__main__':main()
