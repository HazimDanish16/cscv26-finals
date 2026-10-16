#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include <omp.h>
int main(int argc,char**argv){
  uint8_t rk[112],base[16];
  for(int i=0;i<112;i++){unsigned v;sscanf(argv[1]+2*i,"%2x",&v);rk[i]=v;}
  for(int i=0;i<16;i++){unsigned v;sscanf(argv[2]+2*i,"%2x",&v);base[i]=v;}
  __m128i k[7];for(int i=0;i<7;i++)k[i]=_mm_loadu_si128((__m128i*)(rk+16*i));
  static uint64_t H[4][256]; memset(H,0,sizeof H);
  #pragma omp parallel
  { uint64_t h[4][256]; memset(h,0,sizeof h); uint8_t p[16],c[16]; memcpy(p,base,16);
    #pragma omp for schedule(static)
    for(uint64_t i=0;i<(1ULL<<32);i++){
      p[0]=i;p[5]=i>>8;p[10]=i>>16;p[15]=i>>24;
      __m128i x=_mm_loadu_si128((__m128i*)p); x=_mm_xor_si128(x,k[0]);
      for(int r=1;r<=4;r++) x=_mm_aesenc_si128(x,k[r]);
      _mm_storeu_si128((__m128i*)c,x);
      h[0][c[0]]++;h[1][c[5]]++;h[2][c[10]]++;h[3][c[15]]++;
    }
    #pragma omp critical
    for(int a=0;a<4;a++)for(int b=0;b<256;b++)H[a][b]+=h[a][b];
  }
  for(int a=0;a<4;a++){uint64_t mn=~0ULL,mx=0;for(int b=0;b<256;b++){if(H[a][b]<mn)mn=H[a][b];if(H[a][b]>mx)mx=H[a][b];}printf("diag%d min=%lu max=%lu (2^24=%lu)\n",a,mn,mx,1UL<<24);}
}
