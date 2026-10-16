#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <omp.h>
static uint8_t SB[256],IS[256];
static uint8_t gm(uint8_t a,uint8_t b){uint8_t p=0;while(b){if(b&1)p^=a;a=(a<<1)^((a&128)?27:0);b>>=1;}return p;}
static void initsb(){ // compute sbox
  uint8_t p=1,q=1;
  do{ p=p^(p<<1)^((p&128)?27:0); q^=q<<1;q^=q<<2;q^=q<<4; if(q&128)q^=9;
      uint8_t x=q^((q<<1)|(q>>7))^((q<<2)|(q>>6))^((q<<3)|(q>>5))^((q<<4)|(q>>4)); SB[p]=x^0x63;}while(p!=1);
  SB[0]=0x63; for(int i=0;i<256;i++)IS[SB[i]]=i; }
int main(int argc,char**argv){
  initsb();
  // args: file q0 q1 q2 q3 (hex bytes for rows 0..3) 
  int fd=open(argv[1],O_RDONLY); struct stat st; fstat(fd,&st);
  uint64_t *m=mmap(0,st.st_size,PROT_READ,MAP_SHARED,fd,0); uint64_t *B=m+2;
  uint8_t q[4]; for(int i=0;i<4;i++)q[i]=strtoul(argv[2+i],0,16);
  uint8_t Mi[4][4]={{14,11,13,9},{9,14,11,13},{13,9,14,11},{11,13,9,14}};
  uint8_t T[4][256]; for(int r=0;r<4;r++)for(int x=0;x<256;x++)T[r][x]=IS[x^q[r]];
  static uint8_t H[4][256]; memset(H,0,sizeof H);
  #pragma omp parallel
  { uint8_t h[4][256]; memset(h,0,sizeof h);
    #pragma omp for schedule(static)
    for(uint64_t wi=0;wi<(1ULL<<26);wi++){ uint64_t w=B[wi]; while(w){ int b=__builtin_ctzll(w); w&=w-1; uint32_t idx=(wi<<6)|b;
        uint8_t t[4]={T[0][idx&255],T[1][(idx>>8)&255],T[2][(idx>>16)&255],T[3][idx>>24]};
        for(int j=0;j<4;j++){uint8_t y=0;for(int r=0;r<4;r++)y^=gm(Mi[j][r],t[r]);h[j][y]^=1;} } }
    #pragma omp critical
    for(int j=0;j<4;j++)for(int y=0;y<256;y++)H[j][y]^=h[j][y];
  }
  for(int j=0;j<4;j++){ int ones=0; for(int y=0;y<256;y++)ones+=H[j][y]; printf("j=%d H ones=%d  kappa with sum==0:",j,ones);
    for(int k=0;k<256;k++){uint8_t a=0;for(int y=0;y<256;y++)if(H[j][y])a^=IS[y^k];if(!a)printf(" %02x",k);} printf("\n"); }
}
