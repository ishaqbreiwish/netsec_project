"""Build a portable data/code ZIP and checksums; no network access."""
import argparse
import hashlib
import json
import zipfile
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, default=Path('artifacts/netsec-data-handoff.zip'))
    a = p.parse_args()
    roots = [Path('netsec'), Path('tests'), Path('data')]
    files = [p for root in roots for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc']
    files += list(Path('.').glob('*.md'))
    files = sorted(set(files))
    manifest = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(a.output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for path in files:
            z.write(path, str(Path('netsec-data-handoff') / path))
        z.writestr('netsec-data-handoff/HANDOFF_MANIFEST.json', json.dumps(manifest, indent=2) + '\n')
    digest = hashlib.sha256(a.output.read_bytes()).hexdigest()
    a.output.with_name('SHA256SUMS').write_text(f'{digest}  {a.output.name}\n')
    print(f'{a.output}: {len(files)} files, {a.output.stat().st_size:,} bytes; SHA256 {digest}')

if __name__ == '__main__':
    main()
