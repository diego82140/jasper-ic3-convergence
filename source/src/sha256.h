/* SHA-256 for executable identity checks. No external initialization required. */
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct { uint32_t s[8]; uint64_t bytes; unsigned n; unsigned char b[64]; } js_sha;
static uint32_t js_rotr(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
static void js_block(js_sha *c,const unsigned char *b){
 static const uint32_t k[64]={
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
 uint32_t w[64];for(int i=0;i<16;i++)w[i]=((uint32_t)b[4*i]<<24)|((uint32_t)b[4*i+1]<<16)|((uint32_t)b[4*i+2]<<8)|b[4*i+3];
 for(int i=16;i<64;i++){uint32_t a=w[i-15],z=w[i-2];w[i]=w[i-16]+(js_rotr(a,7)^js_rotr(a,18)^(a>>3))+w[i-7]+(js_rotr(z,17)^js_rotr(z,19)^(z>>10));}
 uint32_t a=c->s[0],d=c->s[3],b0=c->s[1],cc=c->s[2],e=c->s[4],f=c->s[5],g=c->s[6],h=c->s[7];
 for(int i=0;i<64;i++){uint32_t t=h+(js_rotr(e,6)^js_rotr(e,11)^js_rotr(e,25))+((e&f)^(~e&g))+k[i]+w[i];uint32_t u=(js_rotr(a,2)^js_rotr(a,13)^js_rotr(a,22))+((a&b0)^(a&cc)^(b0&cc));h=g;g=f;f=e;e=d+t;d=cc;cc=b0;b0=a;a=t+u;}
 c->s[0]+=a;c->s[1]+=b0;c->s[2]+=cc;c->s[3]+=d;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}
static void js_update(js_sha*c,const unsigned char*b,size_t n){c->bytes+=n;while(n){size_t a=64-c->n;if(a>n)a=n;memcpy(c->b+c->n,b,a);c->n+=a;b+=a;n-=a;if(c->n==64){js_block(c,c->b);c->n=0;}}}
static int jipstats_sha256_file(FILE*f,char hex[65]){
 js_sha c={{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19},0,0,{0}};
 unsigned char b[65536];size_t n;while((n=fread(b,1,sizeof b,f)))js_update(&c,b,n);if(ferror(f))return 0;
 uint64_t bits=c.bytes*8;c.b[c.n++]=0x80;if(c.n>56){memset(c.b+c.n,0,64-c.n);js_block(&c,c.b);c.n=0;}memset(c.b+c.n,0,56-c.n);for(int i=0;i<8;i++)c.b[63-i]=(unsigned char)(bits>>(8*i));js_block(&c,c.b);
 static const char digits[]="0123456789abcdef";for(int i=0;i<32;i++){unsigned v=(c.s[i/4]>>(24-8*(i%4)))&255;hex[i*2]=digits[v>>4];hex[i*2+1]=digits[v&15];}hex[64]=0;return 1;
}
