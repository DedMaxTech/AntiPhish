"""Paired Fast/offline regression with and without both local text models."""
import argparse
import json
from pathlib import Path
from antiphish.analyzer import Analyzer
from antiphish.dataset import benchmark_dataset


class ModelAnalyzer(Analyzer):
    def analyze(self,*args,**kwargs):
        kwargs['options']={'laya':True,'text_model':True,'render_local':False,'visual_brands':False}
        return super().analyze(*args,**kwargs)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('archive',type=Path);parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();args.output_dir.mkdir(parents=True,exist_ok=False)
    summary={}
    for name,analyzer in [('baseline',Analyzer()),('models',ModelAnalyzer())]:
        result=benchmark_dataset(args.archive,analyzer,profile='fast',network='offline',output=args.output_dir/(name+'.json'),progress=lambda n:print(name,n,flush=True))
        summary[name]={'metrics':result['metrics'],'seconds':result['elapsed_seconds'],
                       'ai_decisions':sum('AI_MODEL_REVIEW' in row.get('decisive_reasons',[]) for row in result['rows'])}
        print(name,json.dumps(summary[name],ensure_ascii=True),flush=True)
    (args.output_dir/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')


if __name__=='__main__':main()
