import struct,sys,datetime
d=open(sys.argv[1],'rb').read()
R={1:'OVERWRITE',2:'EXTEND',4:'TRUNC',0x100:'CREATE',0x200:'DELETE',0x1000:'RENAME_OLD',0x2000:'RENAME_NEW',0x80000000:'CLOSE',0x20:'?',0x8000:'BASIC',0x800:'SEC',0x400:'EA'}
i=0;n=len(d)
while i<n-60:
    l=struct.unpack('<I',d[i:i+4])[0]
    if l==0: i+=8;continue
    if l<60 or l>1024 or i+l>n or d[i+4:i+6]!=b'\x02\x00': i+=8;continue
    mft,seq,pmft,pseq,usn,ts,reason,src,sec,attr,nl,no=struct.unpack('<QQQQQqIIIIHH',d[i+8:i+8+0x38][:0x38]) if False else (None,)*12
    mft=struct.unpack('<Q',d[i+8:i+16])[0]&0xffffffffffff
    pm=struct.unpack('<Q',d[i+16:i+24])[0]&0xffffffffffff
    usn=struct.unpack('<q',d[i+24:i+32])[0]
    ts=struct.unpack('<q',d[i+32:i+40])[0]
    reason=struct.unpack('<I',d[i+40:i+44])[0]
    nl,no=struct.unpack('<HH',d[i+56:i+60])
    nm=d[i+no:i+no+nl].decode('utf-16le','replace')
    t=datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=ts//10)
    rs='|'.join(v for k,v in R.items() if reason&k)
    print(f'{t} mft={mft} par={pm} {rs:30} {nm}')
    i+=(l+7)&~7
