"""Verify recorded evidence in a separate working directory."""
from pathlib import Path
import argparse, hashlib, json, shutil, subprocess, sys, tempfile, zipfile

ROOT=Path(__file__).resolve().parent

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--quick',action='store_true',help='Skip Java/TLC; retain the Z3 inductive checks')
    ap.add_argument('--work-dir',type=Path,help='New or empty directory; all regenerated files stay here')
    args=ap.parse_args()
    work=args.work_dir.resolve() if args.work_dir else Path(tempfile.mkdtemp(prefix='mem-inv-v2-'))
    if work==ROOT or ROOT.is_relative_to(work) or work.is_relative_to(ROOT):
        ap.error('Use a working directory outside the artifact folder.')
    if work.exists() and any(work.iterdir()):
        ap.error('Working directory must be new or empty.')
    work.mkdir(parents=True,exist_ok=True)
    manifest=json.loads((ROOT/'PACKAGE-MANIFEST.json').read_text(encoding='utf-8'))
    for entry in manifest:
        p=(ROOT/entry['path']).resolve()
        assert p.is_relative_to(ROOT) and hashlib.sha256(p.read_bytes()).hexdigest()==entry['sha256'],entry['path']
    for folder in ('code','formal','vendor'):
        shutil.copytree(ROOT/folder,work/folder)
    for name in ('verify_evidence.py','reported_values.json'):
        shutil.copy2(ROOT/name,work/name)
    archive=ROOT/'evidence/recorded-evidence.zip'
    release=json.loads((ROOT/'release.json').read_text())
    assert hashlib.sha256(archive.read_bytes()).hexdigest()==release['evidence_sha256']
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        entries=json.loads(z.read('EVIDENCE-MANIFEST.json'))
        for entry in entries:
            assert (work/entry['path']).resolve().is_relative_to(work)
            assert hashlib.sha256(z.read(entry['path'])).hexdigest()==entry['sha256']
        z.extractall(work)
    extra=release.get('additional_evidence')
    if extra:
        archive=ROOT/extra['archive']
        assert hashlib.sha256(archive.read_bytes()).hexdigest()==extra['sha256']
        with zipfile.ZipFile(archive) as z:
            assert z.testzip() is None
            entries=json.loads(z.read('ACTION-EVIDENCE-MANIFEST.json'))
            for entry in entries:
                assert (work/entry['path']).resolve().is_relative_to(work)
                assert hashlib.sha256(z.read(entry['path'])).hexdigest()==entry['sha256']
            assert set(z.namelist())=={e['path'] for e in entries}|{'ACTION-EVIDENCE-MANIFEST.json'}
            z.extractall(work)
    # Unmodified analysis code exports numeric LaTeX tables to this temporary
    # directory. No manuscript source or PDF is shipped or needed.
    (work/'paper').mkdir()
    command=[sys.executable,'-X','utf8',str(work/'verify_evidence.py')]
    if args.quick:command.append('--quick')
    print('Working copy:',work,flush=True)
    with (work/'verification.log').open('w',encoding='utf-8') as stream:
        result=subprocess.run(command,cwd=work,stdout=stream,stderr=subprocess.STDOUT)
    report=dict(exit_code=result.returncode,mode='quick' if args.quick else 'full',
        manuscript_included=False,scope='Numeric reference data, source integrity, recorded experiments and formal checks; no manuscript prose validation.',
        independent_validation='Requires a separate evaluator; not inferred by this program.')
    (work/'verification-report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
    print('Full log:',work/'verification.log')
    return result.returncode

if __name__=='__main__':raise SystemExit(main())
