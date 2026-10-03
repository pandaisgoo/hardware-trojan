#!/usr/bin/env python3
"""Re-evaluate an unchanged detector using locally supplied labeled netlists.
Added during portfolio preparation; not part of the submitted detector.
Python 3.10+, standard library only. No network requests.
Labels are read only by this evaluator; each detector input is staged as input.v.
The scoring rules match the score.py supplied with the uploaded benchmark.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, platform, re, shutil, statistics
import subprocess, tempfile, time
from pathlib import Path

def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def parse_result(p: Path) -> tuple[str,set[str]]:
    tokens=p.read_text(errors='replace').split() if p.is_file() else []
    if not tokens: return 'INVALID',set()
    label=tokens[0].upper()
    if label=='NO_TROJAN': return label,set()
    if label!='TROJANED': return 'INVALID',set()
    gates=set(); active=False
    for token in tokens[1:]:
        if token=='TROJAN_GATES': active=True; continue
        if token=='END_TROJAN_GATES': active=False; continue
        if active: gates.add(token)
    return label,gates

def f1_score(pred:set[str],truth:set[str])->float:
    if not pred and not truth: return 1.0
    if not pred or not truth: return 0.0
    return 2*len(pred & truth)/(len(pred)+len(truth))

def main()->None:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary',required=True,type=Path)
    ap.add_argument('--cases',required=True,type=Path)
    ap.add_argument('--out',required=True,type=Path)
    ap.add_argument('--source',type=Path)
    ap.add_argument('--timeout',type=float,default=180)
    a=ap.parse_args()
    binary=a.binary.resolve(); cases=a.cases.resolve(); out=a.out.resolve()
    if not binary.is_file(): ap.error('Binary not found; build first.')
    if not cases.is_dir(): ap.error('Case directory not found.')
    if a.timeout<=0: ap.error('Timeout must be positive.')
    if out.exists() and any(out.iterdir()): ap.error('Output directory must be new or empty.')
    designs=sorted((p for p in cases.glob('design*.v') if re.fullmatch(r'design\d+\.v',p.name)),key=lambda p:int(p.stem[6:]))
    if not designs: ap.error('No designN.v files found.')
    if any(not (cases/f'result{p.stem[6:]}.txt').is_file() for p in designs): ap.error('Missing reference result file.')
    out.mkdir(parents=True,exist_ok=True); (out/'predictions').mkdir(); (out/'logs').mkdir()
    fields=['case','ground_truth','prediction','exit_code','timed_out','wall_seconds','label_correct','reference_gates','predicted_gates','gate_tp','gate_fp','gate_fn','gate_precision','gate_recall','gate_f1','format_valid','unknown_gate_ids','score','max_score']
    rows=[]; manifest=[]; start=time.perf_counter()
    with (out/'per_case.csv').open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields); writer.writeheader()
        for i,design in enumerate(designs,1):
            ident=design.stem[6:]; ref=cases/f'result{ident}.txt'
            gt,gg=parse_result(ref)
            if gt not in ('NO_TROJAN','TROJANED'): raise ValueError(f'Invalid reference: {ref}')
            with tempfile.TemporaryDirectory(prefix='trojan_eval_') as tmp:
                stage=Path(tmp); inp=stage/'input.v'; pred=stage/'output.txt'
                shutil.copyfile(design,inp); inp.chmod(0o444)
                timed_out=False; t0=time.perf_counter()
                try:
                    proc=subprocess.run([str(binary),str(inp),str(pred)],cwd=stage,capture_output=True,timeout=a.timeout)
                    rc=proc.returncode; log=proc.stdout+proc.stderr
                except subprocess.TimeoutExpired as exc:
                    rc=124; timed_out=True; log=(exc.stdout or b'')+(exc.stderr or b'')
                elapsed=time.perf_counter()-t0
                (out/'logs'/f'{design.stem}.log').write_bytes(log)
                saved=out/'predictions'/f'result{ident}.txt'
                saved.write_bytes(pred.read_bytes() if pred.is_file() else b'')
            pl,pg=parse_result(saved); positive=gt=='TROJANED'
            tp=len(pg & gg); fp=len(pg-gg); fn=len(gg-pg)
            f1=f1_score(pg,gg) if positive and pl=='TROJANED' else 0.0
            score=2.0 if not positive and pl=='NO_TROJAN' else 2.0+f1 if positive and pl=='TROJANED' else 0.0
            names=set(re.findall(r'\b(?:and|or|nand|nor|xor|xnor|not|buf|dff)\s+(g\d+)\s*\(',design.read_text(),re.IGNORECASE))
            tokens=saved.read_text(errors='replace').split()
            valid=tokens==['NO_TROJAN'] or (len(tokens)>=3 and tokens[0]=='TROJANED' and tokens[1]=='TROJAN_GATES' and tokens[-1]=='END_TROJAN_GATES' and all(re.fullmatch(r'g\d+',x) for x in tokens[2:-1]))
            row=dict(case=design.stem,ground_truth=gt,prediction=pl,exit_code=rc,timed_out=timed_out,wall_seconds=elapsed,label_correct=gt==pl,reference_gates=len(gg),predicted_gates=len(pg),gate_tp=tp,gate_fp=fp,gate_fn=fn,gate_precision=tp/len(pg) if pg else 0.0,gate_recall=tp/len(gg) if gg else 0.0,gate_f1=f1,format_valid=bool(valid),unknown_gate_ids=len(pg-names),score=score,max_score=3 if positive else 2)
            rows.append(row); writer.writerow(row); f.flush()
            manifest.append(dict(case=design.stem,input_sha256=sha(design),reference_sha256=sha(ref),prediction_sha256=sha(saved)))
            if i%30==0 or i==len(designs): print(f'{i}/{len(designs)}; {time.perf_counter()-start:.1f}s',flush=True)
    positive=[r for r in rows if r['ground_truth']=='TROJANED']; negative=[r for r in rows if r['ground_truth']=='NO_TROJAN']
    tp=sum(r['prediction']=='TROJANED' for r in positive); tn=sum(r['prediction']=='NO_TROJAN' for r in negative)
    fp=sum(r['prediction']=='TROJANED' for r in negative); fn=sum(r['prediction']=='NO_TROJAN' for r in positive)
    found=[r for r in positive if r['prediction']=='TROJANED']
    summary=dict(environment=platform.platform(),binary_sha256=sha(binary),source_sha256=sha(a.source) if a.source else None,case_count=len(rows),positive_cases=len(positive),negative_cases=len(negative),confusion=dict(tp=tp,tn=tn,fp=fp,fn=fn),invalid_predictions=sum(r['prediction']=='INVALID' for r in rows),label_correct=tp+tn,label_accuracy=(tp+tn)/len(rows),positive_precision=tp/(tp+fp) if tp+fp else 0.0,positive_recall=tp/len(positive) if positive else 0.0,mean_gate_f1_all_positive=sum(r['gate_f1'] for r in positive)/len(positive) if positive else 0.0,mean_gate_f1_true_positive=sum(r['gate_f1'] for r in found)/len(found) if found else 0.0,exact_positive_gate_sets=sum(r['prediction']=='TROJANED' and r['gate_fp']==0 and r['gate_fn']==0 for r in positive),score=sum(r['score'] for r in rows),max_score=sum(r['max_score'] for r in rows),nonzero_exits=sum(r['exit_code']!=0 for r in rows),timeouts=sum(r['timed_out'] for r in rows),invalid_formats=sum(not r['format_valid'] for r in rows),unknown_gate_id_cases=sum(r['unknown_gate_ids']!=0 for r in rows),median_wall_seconds=statistics.median(r['wall_seconds'] for r in rows),max_wall_seconds=max(r['wall_seconds'] for r in rows),total_run_wall_seconds=sum(r['wall_seconds'] for r in rows),note='One run on uploaded public_cases; not hidden-set performance. Detector unchanged. Gate F1 is zero for missed positive cases. Scoring matches supplied score.py; format/exit checks are separately reported. Timing is from a shared container and is not a dedicated performance benchmark.')
    summary['score_fraction']=summary['score']/summary['max_score']
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps(summary,indent=2),flush=True)
if __name__=='__main__': main()
