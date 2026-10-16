import struct,sys
d=open(sys.argv[1],'rb').read()
names={}
recs=[]
for i in range(len(d)//1024):
    r=bytearray(d[i*1024:(i+1)*1024])
    if r[:4]!=b'FILE': 
        if any(r[:16]): print(i,'nonFILE',bytes(r[:8]))
        continue
    # fixups
    uo,uc=struct.unpack('<HH',r[4:8])
    for k in range(1,uc):
        r[k*512-2:k*512]=r[uo+2*k:uo+2*k+2]
    flags=struct.unpack('<H',r[22:24])[0]
    off=struct.unpack('<H',r[20:22])[0]
    fn=[];data=[]
    while off<1024-4:
        t,l=struct.unpack('<II',r[off:off+8])
        if t==0xffffffff or l==0:break
        if t==0x30 and r[off+8]==0:
            co=struct.unpack('<H',r[off+20:off+22])[0]
            c=r[off+co:off+l]
            par=struct.unpack('<Q',c[:8])[0]&0xffffffffffff
            nl=c[64];ns=c[65]
            nm=c[66:66+nl*2].decode('utf-16le','replace')
            fn.append((par,ns,nm))
        if t==0x80:
            data.append((r[off+8],r[off+9]))
        off+=l
    recs.append((i,flags,fn,data))
    for p,ns,nm in fn: names[i]=nm
for i,fl,fn,data in recs:
    if i<24: continue
    print(i,hex(fl),[(p,n) for p,ns,n in fn if ns!=2],'res' if data and data[0][0]==0 else 'nonres' if data else '')
