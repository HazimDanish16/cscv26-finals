import re
FLAG_RE = re.compile(rb'(?i)(cscv|flag|ctf)\{[^}\n]{1,200}\}')


def find_flags(data):
    if isinstance(data, str):
        data = data.encode(errors='ignore')
    return [m.group(0).decode(errors='ignore') for m in FLAG_RE.finditer(data)]
