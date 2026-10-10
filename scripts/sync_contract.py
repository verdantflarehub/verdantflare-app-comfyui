"""Generate the build copy from verdantflare-design; never edit the copy."""
import argparse
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    raw = args.source.read_bytes()
    definition = json.loads(raw)
    for tool in definition['tools']:
        Draft202012Validator.check_schema(tool['inputSchema'])
    value = {'generated_from': 'verdantflare-design/docs/design/app/comfyui/mcp-tools.dev.json',
             'source_sha256': hashlib.sha256(raw).hexdigest(), **definition}
    encoded = json.dumps(value, ensure_ascii=False, indent=2) + '\n'
    output = ROOT / 'app/generated_tools.json'
    if args.check:
        if not output.exists() or output.read_text(encoding='utf-8') != encoded:
            raise SystemExit('generated contract differs from source')
    else:
        output.write_text(encoded, encoding='utf-8', newline='\n')


if __name__ == '__main__':
    main()
