import ctypes,sys,os,time
sys.path.insert(0,".")
from aes import AES6
key=bytes.fromhex(open("key.txt").read().split()[0])
c=AES6(key)
base=os.urandom(16)
tag=sys.argv[1]
a=ctypes.create_string_buffer(b"".join(bytes(x for col in k for x in col) for k in c.keys))
b=ctypes.create_string_buffer(base)
lib=ctypes.CDLL("./core.so")
lib.make_bitmap.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_char_p]
t=time.time(); r=lib.make_bitmap(a,b,1<<32,("loc_%s.bt"%tag).encode()); print("ret",r,time.time()-t)
open("loc_%s.base"%tag,"w").write(base.hex())
