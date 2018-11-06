/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: sampling functions
**************************************************************************************/

#include "api.h"
#include "sample.h"
#include "params.h"
#include "random/random.h"
#include "sha3/fips202.h"

#define round_double(x)   (uint64_t)(x+0.5)
#define NBLOCKS_SHAKE     SHAKE_RATE/(((PARAM_B_BITS+1)+7)/8)
#define BPLUS1BYTES       ((PARAM_B_BITS+1)+7)/8


void sample_y(poly y, const unsigned char *seed, int nonce)
{ // Sample polynomial y, such that each coefficient is in the range [-B,B]
  unsigned int i=0, pos=0, nblocks = PARAM_N;
  unsigned char buf[PARAM_N*BPLUS1BYTES];
  unsigned int nbytes = BPLUS1BYTES;
  int16_t dmsp = (int16_t)(nonce<<8);
  sdigit32_t y_t[4];
    
  cSHAKE((uint8_t*)buf, PARAM_N*nbytes, dmsp++, seed, CRYPTO_RANDOMBYTES);

  while (i<PARAM_N) {
    if (pos >= nblocks*nbytes*4) {
      nblocks = NBLOCKS_SHAKE;
      cSHAKE((uint8_t*)buf, SHAKE_RATE, dmsp++, seed, CRYPTO_RANDOMBYTES);
      pos = 0;
    }
    y_t[0]  = (*(uint32_t*)(buf+pos))          & ((1<<(PARAM_B_BITS+1))-1);
    y_t[1]  = (*(uint32_t*)(buf+pos+nbytes))   & ((1<<(PARAM_B_BITS+1))-1);
    y_t[2]  = (*(uint32_t*)(buf+pos+2*nbytes)) & ((1<<(PARAM_B_BITS+1))-1);
    y_t[3]  = (*(uint32_t*)(buf+pos+3*nbytes)) & ((1<<(PARAM_B_BITS+1))-1);
    y_t[0] -= PARAM_B;
    y_t[1] -= PARAM_B;
    y_t[2] -= PARAM_B;
    y_t[3] -= PARAM_B;
    if (y_t[0] != (1<<PARAM_B_BITS))
      y[i++] = y_t[0];
    if (i<PARAM_N && y_t[1] != (1<<PARAM_B_BITS))
      y[i++] = y_t[1];
    if (i<PARAM_N && y_t[2] != (1<<PARAM_B_BITS))
      y[i++] = y_t[2];
    if (i<PARAM_N && y_t[3] != (1<<PARAM_B_BITS))
      y[i++] = y_t[3];
    pos += 4*nbytes;
  }
}


void encode_c(uint32_t *pos_list, int16_t *sign_list, unsigned char *c_bin)
{ // Encoding of c' by mapping the output of the hash function H to an N-element vector with entries {-1,0,1} 
  int i, pos, cnt=0;
  int16_t c[PARAM_N];
  unsigned char r[SHAKE128_RATE];
  uint16_t dmsp=0;
  
  // Use the hash value as key to generate some randomness
  cshake128_simple(r, SHAKE128_RATE, dmsp++, c_bin, CRYPTO_RANDOMBYTES);

  // Use rejection sampling to determine positions to be set in the new vector
  for (i=0; i<PARAM_N; i++)
    c[i] = 0;

  for (i=0; i<PARAM_H;) {     // Sample a unique position k times. Use two bytes
    if (cnt > (SHAKE128_RATE - 3)) {
      cshake128_simple(r, SHAKE128_RATE, dmsp++, c_bin, CRYPTO_RANDOMBYTES);  
      cnt = 0; 
    }
    pos = (r[cnt]<<8) | (r[cnt+1]);
    pos = pos & (PARAM_N-1);  // Position is in the range [0,N-1]

    if (c[pos] == 0) {        // Position has not been set yet. Determine sign
      if ((r[cnt+2] & 1) == 1)
        c[pos] = -1;
      else
        c[pos] = 1;
      pos_list[i] = pos;
      sign_list[i] = c[pos];
      i++;
    }
    cnt += 3;
  }
}


static int64_t mod7(int64_t k)
{ // Compute k modulo 7 
    int64_t i = k;

    for (int j = 0; j < 2; j++) {
        i = (i & 7) + (i >> 3);
    }
    // i <= 7 at this point. If (i == 7) return 0, else return i
    return  ((i-7) >> 3) & i;
}


static uint32_t Bernoulli(int64_t r, int64_t t)
{ // Sample a bit from Bernoulli
  // Restriction: 15-bit exponent
    static const double exp[3][32] = {
    { 1.000000000000000000000000000000000000000, 0.9990496327075997720621566739241504871513, 0.9981001686131900082646604498429491608001, 0.9971516068584008799087793737854343387385, 0.9962039465856783249057599531380206128030, 0.9952571869382832724989228009014122394200, 0.9943113270602908687225570427678069689363, 0.9933663660965897025969132575731249565771, 0.9924223031928810330585953871541593536283, 0.9914791374956780166256527164832613053574, 0.9905368681523049357966736891640434381216, 0.9895954943108964281831839869512129866330, 0.9886550151203967163746519649066284074237, 0.9877154297305588385354051961226109899227, 0.9867767372919438797327625416330343864518, 0.9858389369559202039956868221933583419625, 0.9849020278746626871032638290431658501235, 0.9839660092011519501023140705695025630520, 0.9830308800891735935534443109670000387768, 0.9820966396933174325048466155419862577528, 0.9811632871689767321931532752331431453491, 0.9802308216723474444706566402213564033800, 0.9792992423604274449582035491768120172661, 0.9783685483910157709230746967427200384407, 0.9774387389227118598811599372828827520575, 0.9765098131149147889227411777252636721429, 0.9755817701278225147611951665163479411869, 0.9746546091224311145039291392620050672727, 0.9737283292605340271448629345703623656609, 0.9728029297047212957777718459314622781631, 0.9718784096183788105298051271677986565965, 0.9709547681656875522144957200697952895280, },
    { 1.000000000000000000000000000000000000000, 0.9700320045116228367035774232914930379400, 0.9409620897768370674212298508058219852849, 0.9127633421156708668942503744059309052528, 0.8854096543971923811501043960464255901147, 0.8588757018688517364879932717859212289637, 0.8331369187101692180902460141030849026557, 0.8081694752890624155161689578277768341910, 0.7839502560997556536888618983783791053116, 0.7604568383618460545183896873859249753543, 0.7376674712607126902372883387750345338472, 0.7155610558100490615694685434237323547987, 0.6941171253178751117406951384261687867164, 0.6733158264379437043232142381368341940533, 0.6531379007889984662634253213819854052726, 0.6335646671248656289427239706049936967143, 0.6145780040388724765036124496076447154217, 0.5961603331865797040852326968966728810261, 0.5782946030112948570545930362131434268247, 0.5609642729572995100665682618108293115511, 0.5441532981561743827978648643747061873131, 0.5278461145720445955231454653404664082188, 0.5120276245919921478529972155927751107378, 0.4966831830482948512984566287866591847562, 0.4817985836595507424420546966358580262381, 0.4673600458781348185224193866260805625424, 0.4533542021318111302275642196084653301628, 0.4397680854476881857303133336231578259611, 0.4265891174470596033395475021945475958821, 0.4138050967000153253100465421861800587782, 0.4014041874290417902572763743098032661210, 0.3893749085511525646401543103372782315254, },
    { 1.000000000000000000000000000000000000000, 0.3777061230484043540417651455683576466650, 0.1426619153882563708052119679085105421822, 0.05388427896795781140761650507038592985458, 0.02035242210224601989078627211632756962058, 0.007687234446883999610174328676334715949640, 0.002903515519896700541261482818225051140099, 0.001096675590231054915122715889282581559573, 0.0004142210854279922997296008273437255752956, 0.0001564538402619088712753422615493598849163, 5.909357344135995142394679824207999201121E-5, 2.232000452161222135025591154935960584027E-5, 8.430402374281007236700902260035220289887E-6, 3.184214596527742337148476455363347356131E-6, 1.202697350208632670782595114365065060885E-6, 4.542661533478916755570208360842380811059E-7, 1.715791076131440947144583312662638239090E-7, 6.480647953266561572601959656715022445021E-8, 2.447780413269889735078224512008720987199E-8, 9.245416499699910342143072277116651273927E-9, 3.492050422069402212293514861017928736701E-9, 1.318968826409377991494549187659977485249E-9, 4.981826018447900060525041555590742055479E-10, 1.881666191129624879723808164319051826703E-10, 7.107168419228284402686789774896404982106E-11, 2.684421029478771850078976357840397379201E-11, 1.013922259674033292202917547107956246173E-11, 3.829646457739566105989785588606755995719E-12, 1.446480916198866420590826731657500079699E-12, 5.463446989209777070985952848270039796153E-13, 2.063577380774902353530525926195322827410E-13, 7.794258121028692337871970872695782456164E-14, },
    }; 

    // Compute the actual Bernoulli parameter c = exp(-t/f):
    double c = 4611686018427387904.0;  // This yields a fraction of 2^62, to keep only 62 bits of precision in this implementation

    for (int64_t i = 0, s = t; i < 3; i++, s >>= 5) {
        c *= exp[i][s & 31]; 
    }
    // Sample from Bernoulli_c
    return (uint32_t)((uint64_t)((r & 0x3FFFFFFFFFFFFFFFLL) - round_double(c)) >> 63);
}


void sample_gauss_poly(poly x, const unsigned char *seed, int nonce)
{ // Gaussian sampler
  static const int64_t cdt[12][2] = {
   {0x0200000000000000LL, 0x0000000000000000LL},
   {0x0300000000000000LL, 0x0000000000000000LL},
   {0x0320000000000000LL, 0x0000000000000000LL},
   {0x0321000000000000LL, 0x0000000000000000LL},
   {0x0321020000000000LL, 0x0000000000000000LL},
   {0x0321020100000000LL, 0x0000000000000000LL},
   {0x0321020100200000LL, 0x0000000000000000LL},
   {0x0321020100200100LL, 0x0000000000000000LL},
   {0x0321020100200100LL, 0x0200000000000000LL},
   {0x0321020100200100LL, 0x0200010000000000LL},
   {0x0321020100200100LL, 0x0200010000200000LL},
   {0x0321020100200100LL, 0x0200010000200001LL}, 
  };  

  unsigned char seed_ex[PARAM_N*8]; 
  int64_t i, j=0, x_ind;
  int64_t *buf = (int64_t*)seed_ex;
  int64_t sign, k, bitsremained, rbits, y, z;
  uint64_t r, s;
  int16_t dmsp = (int16_t)(nonce<<8);

  cSHAKE(seed_ex, PARAM_N*8, dmsp++, seed, CRYPTO_RANDOMBYTES);

  for (x_ind=0; x_ind<PARAM_N; x_ind++){
    if ((j+46) > (PARAM_N)){
      cSHAKE((uint8_t*)buf, PARAM_N*8, dmsp++, seed, CRYPTO_RANDOMBYTES);
      j=0;
    }
    do {
      rbits=buf[j++]; bitsremained=64;
      do {
        // Sample x from D^+_{\sigma_2} and y from U({0, ..., k-1}):
        do {
          r = buf[j++];
          s = buf[j++];
          if (bitsremained <= 64 - 6) {
            rbits = (rbits << 6) ^ ((r >> 58) & 63); bitsremained += 6;
          }
          r &= 0x03FFFFFFFFFFFFFFLL;
        } while (r > 0x0321020100200100LL);  // Checking if r exceeds a maximum value. Variation is random and does not depend on private data
        y = 0;
        for (i = 0; i < 12; i++) {
          uint64_t c_lo = s - cdt[i][1];
          uint64_t b = (((c_lo & cdt[i][1]) & 1) + (cdt[i][1] >> 1) + (c_lo >> 1)) >> 63;
          uint64_t c_hi = r - (cdt[i][0] + b);
          y += ~(c_hi >> (63)) & 1LL; 
        }
        // The next sampler works exclusively for PARAM_Xi <= 28
        do {
          do {
            if (bitsremained < 6) {
              rbits = buf[j++]; bitsremained = 64;
            }
            z = rbits & 63; rbits >>= 6; bitsremained -= 6;
          } while (z == 63);
          if (bitsremained < 2) {
            rbits = buf[j++]; bitsremained = 64;
          }
          z = (mod7(z) << 2) + (rbits & 3); rbits >>= 2; bitsremained -= 2;
        } while (z >= PARAM_Xi);  // Making sure random z does not exceed a certain limit. No private data leaked, it varies uniformly
        k = PARAM_Xi*y + z;
        // Sample a bit from Bernoulli_{exp(-y*(y + 2*k*x)/(2*k^2*sigma_2^2))}
      } while (Bernoulli(buf[j++], z*((k << 1) - z)) == 0);
      // Put last randombits into sign bit
      rbits <<=(64-bitsremained);
      if (bitsremained==0LL) {
        rbits = buf[j++]; bitsremained=64;
      }
      sign = rbits >> 63; rbits <<= 1; bitsremained--;
    } while ((k | (sign & 1)) == 0);
    if (bitsremained==0LL) {
      rbits = buf[j++]; bitsremained=64;
    }
    sign = rbits >> 63; rbits <<= 1; bitsremained--;
    k = ((k << 1) & sign) - k;
    x[x_ind] = (sdigit32_t)((k<<48)>>48);
  }
}