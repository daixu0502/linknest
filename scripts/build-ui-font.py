#!/usr/bin/env python3
"""Build the bundled UI font from the pinned Google Fonts Noto Sans SC source.

Requires fonttools[woff] and brotli. The source font and build dependencies stay
local; the WOFF2 subset and upstream license are redistributable UI assets.
"""
import argparse
import hashlib
from pathlib import Path
from fontTools import subset
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA256 = 'a3041811a78c361b1de50f953c805e0244951c21c5bd412f7232ef0d899af0da'
LICENSE_SHA256 = '1c05c68c34f9708415aada51f17e1b0092d2cea709bf4a94cd38114f9e73d7d9'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--license', type=Path, required=True)
    args = parser.parse_args()
    for path, expected in [(args.input, SOURCE_SHA256), (args.license, LICENSE_SHA256)]:
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit('Unexpected upstream font or license: ' + path.name)
    text = ''.join(p.read_text(encoding='utf-8') for p in sorted((ROOT/'web').glob('*')) if p.suffix in ['.js', '.html', '.css'])
    codepoints = set(range(32, 127)) | {ord(c) for c in text if ord(c) >= 32}
    font = TTFont(args.input, recalcTimestamp=False)
    options = subset.Options()
    options.name_IDs = ['*']
    options.name_languages = ['*']
    builder = subset.Subsetter(options=options)
    builder.populate(unicodes=codepoints)
    builder.subset(font)
    instantiateVariableFont(font, {'wght': (400, 400, 600)}, inplace=True)
    for name in font['name'].names:
        if name.nameID in [1, 4, 6, 16]:
            name.string = ('LinkNestUI' if name.nameID == 6 else 'LinkNest UI').encode(name.getEncoding())
    destination = ROOT/'web/vendor/linknest-ui.woff2'
    font.flavor = 'woff2'
    font.save(destination)
    (destination.parent/'NotoSansSC-OFL.txt').write_bytes(args.license.read_bytes())
    print(f'{destination.name}: {destination.stat().st_size} bytes; {len(font.getBestCmap())} characters')

if __name__ == '__main__':
    main()
