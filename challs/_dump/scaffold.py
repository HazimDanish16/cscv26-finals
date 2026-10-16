import json, os, re

d = json.load(open('challs.json'))
chs = d['data']
root = os.path.join('..')  # challs/

index_lines = ['# CSCV2026 Finals - Challenge Index\n',
               '| Challenge | Category | Points | Instancer | Status | Flag |',
               '|---|---|---|---|---|---|']

for c in chs:
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', c['name'].lower())
    d_name = f"{c['category']}_{safe_name}"
    folder = os.path.join(root, d_name)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, 'notes.md'), 'w', encoding='utf-8') as f:
        f.write(f"# {c['name']} ({c['category']}, {c['points']}pts)\n\n")
        f.write(f"id: `{c['id']}`\n\n")
        f.write(f"instancer: {bool(c.get('instancerLifetime'))}")
        if c.get('instancerLifetime'):
            f.write(f" (lifetime {c['instancerLifetime']/1000:.0f}s, extendable={c.get('instancerExtendable')}, stoppable={c.get('instancerStoppable')})")
        f.write('\n\n## Description\n\n')
        f.write(c['description'] or '(no description)')
        f.write('\n')
    index_lines.append(f"| {c['name']} | {c['category']} | {c['points']} | {'yes' if c.get('instancerLifetime') else 'no'} | unclaimed | |")

with open(os.path.join(root, 'INDEX.md'), 'w', encoding='utf-8') as f:
    f.write('\n'.join(index_lines) + '\n')

print(f'scaffolded {len(chs)} challenge folders + INDEX.md')
