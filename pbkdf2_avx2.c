/* Four independent BIP39 PBKDF2-HMAC-SHA512 lanes, 2048 rounds, empty passphrase.
   GCC/Clang vector extensions; build with -O3 -mavx2. Passwords <=128 bytes.
   No third-party source code; constants and operations defined by SHA-512. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef uint64_t V __attribute__((vector_size(32)));
static const uint64_t K[80]={
0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};
static const uint64_t IV[8]={0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,
0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,0x510e527fade682d1ULL,
0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
#define SPLAT(x) ((V){(x),(x),(x),(x)})
#define ROT(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define S0(x) (ROT(x,28)^ROT(x,34)^ROT(x,39))
#define S1(x) (ROT(x,14)^ROT(x,18)^ROT(x,41))
#define s0(x) (ROT(x,1)^ROT(x,8)^((x)>>7))
#define s1(x) (ROT(x,19)^ROT(x,61)^((x)>>6))
static void compress(V state[8], const V block[16]){
    V w[16]; memcpy(w,block,sizeof(w));
    V a=state[0],b=state[1],c=state[2],d=state[3];
    V e=state[4],f=state[5],g=state[6],h=state[7];
    for(int t=0;t<80;t++){
        int j=t&15;
        if(t>=16) w[j]=w[j]+s0(w[(t-15)&15])+w[(t-7)&15]+s1(w[(t-2)&15]);
        V t1=h+S1(e)+((e&f)^(~e&g))+SPLAT(K[t])+w[j];
        V t2=S0(a)+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;
    state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
}
static uint64_t read_be(const uint8_t *p){
    uint64_t r=0;for(int j=0;j<8;j++)r=(r<<8)|p[j];return r;
}
static void store_be(uint8_t*p,uint64_t v){
    for(int j=7;j>=0;j--){p[j]=(uint8_t)v;v>>=8;}
}
static void digest64(V out[8],const V initial[8],const V msg[8]){
    V block[16]={0};memcpy(block,msg,8*sizeof(V));
    block[8]=SPLAT(0x8000000000000000ULL);block[15]=SPLAT(1536);
    memcpy(out,initial,8*sizeof(V));compress(out,block);
}
static void four(const uint8_t *input,const uint32_t *lengths,uint8_t *output,size_t lanes){
    V inner[8],outer[8],block[16],u[8],tmp[8],result[8];
    for(int j=0;j<8;j++)inner[j]=outer[j]=SPLAT(IV[j]);
    for(int j=0;j<16;j++){
        V word={0};
        for(size_t lane=0;lane<4;lane++){
            uint8_t bytes[8]={0};
            if(lane<lanes){
                for(int k=0;k<8;k++){
                    size_t pos=(size_t)j*8+k;
                    if(pos<lengths[lane])bytes[k]=input[lane*128+pos];
                }
            }
            word[lane]=read_be(bytes);
        }
        block[j]=word^SPLAT(0x3636363636363636ULL);
    }
    compress(inner,block);
    for(int j=0;j<16;j++)block[j]^=SPLAT(0x6a6a6a6a6a6a6a6aULL);
    compress(outer,block);
    memset(block,0,sizeof(block));
    block[0]=SPLAT(0x6d6e656d6f6e6963ULL); /* mnemonic */
    block[1]=SPLAT(0x0000000180000000ULL); /* block index 1, padding */
    block[15]=SPLAT(1120); /* 128-byte ipad + 12-byte message */
    memcpy(tmp,inner,sizeof(tmp));compress(tmp,block);
    digest64(u,outer,tmp);
    memcpy(result,u,sizeof(result));
    for(int round=1;round<2048;round++){
        digest64(tmp,inner,u);digest64(u,outer,tmp);
        for(int j=0;j<8;j++)result[j]^=u[j];
    }
    for(size_t lane=0;lane<lanes;lane++)
        for(int j=0;j<8;j++)store_be(output+lane*64+j*8,result[j][lane]);
}
int pbkdf2_bip39_batch(const uint8_t *input,const uint32_t *lengths,uint8_t *output,size_t count){
    if(!input||!lengths||!output)return -1;
    for(size_t i=0;i<count;i++)if(lengths[i]>128)return -2;
    for(size_t i=0;i<count;i+=4){
        size_t lanes=count-i<4?count-i:4;
        four(input+i*128,lengths+i,output+i*64,lanes);
    }
    return 0;
}
