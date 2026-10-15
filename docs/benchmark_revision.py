"""Повторяемая проверка ZIP с manifest.jsonl и скорости пакетной обработки.

Пример: python docs/benchmark_revision.py --dataset letters.zip --output-dir reports/check
Дополнительные сохранённые страницы: --extra-dataset pages.zip
Метки не импортируются. Классификатор текста остаётся выключенным, если его
не включили явно через ANTIPHISH_TEXT_MODEL_DIR.
"""
from pathlib import Path
import argparse
import json
import tempfile
import time

from antiphish.analyzer import Analyzer
from antiphish.batch import run_batch
from antiphish.config import DEFAULT_KB
from antiphish.dataset import benchmark_dataset, paired_comparison
from antiphish.kb import initialize_empty_kb
from antiphish.utils import atomic_json

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--dataset',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--kb',type=Path,default=DEFAULT_KB)
    parser.add_argument('--baseline',type=Path)
    parser.add_argument('--extra-dataset',type=Path,action='append',default=[])
    args=parser.parse_args()
    args.output_dir.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='antiphish-quality-') as temp:
        kb=Path(temp)/'empty.sqlite'
        initialize_empty_kb(kb)
        analyzer=Analyzer(kb)
        result=benchmark_dataset(args.dataset,analyzer,output=args.output_dir/'quality-final-540.json')
        print('quality',result['metrics'],flush=True)
        if args.baseline:
            before=json.loads(args.baseline.read_text(encoding='utf-8'))
            atomic_json(args.output_dir/'paired-quality-comparison.json',paired_comparison(before['rows'],result['rows']))
        for archive in args.extra_dataset:
            out=args.output_dir/(archive.stem+'-results.json')
            extra=benchmark_dataset(archive,analyzer,output=out)
            print(archive.name,extra['metrics'],flush=True)
    analyzer=Analyzer(args.kb)
    runs=[]
    for profile in ('fast','quality'):
        output=args.output_dir/('batch-final-'+profile+'.json')
        started=time.perf_counter()
        result=run_batch(args.dataset,analyzer,profile=profile,extensions=['.eml'],pattern='*/eml/*',output=output)
        wall=time.perf_counter()-started
        runs.append({'profile':profile,'network':'offline','runtime':result['configuration']['runtime'],'statistics':result['statistics'],'wall_seconds_including_final_json':wall,'wall_items_per_minute':len(result['results'])*60/wall})
        print('batch',profile,runs[-1],flush=True)
        resumed=run_batch(args.dataset,analyzer,profile=profile,extensions=['.eml'],pattern='*/eml/*',output=output,resume=True)
        print('resume',profile,resumed['statistics'],flush=True)
    atomic_json(args.output_dir/'performance-final.json',{'runs':runs,'note':'One pass per profile; same persistent analyzer; JSONL time included, full export time measured separately. Offline performance on this dataset is not browser/deep capacity. Deep excluded from this script.'})

if __name__=='__main__':
    main()
