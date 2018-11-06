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
    { 1.000000000000000000000000000000000000000, 0.9914791374956780166256527164832613053571, 0.9830308800891735935534443109670000387763, 0.9746546091224311145039291392620050672719, 0.9663497112088951922951613058690022829314, 0.9581155781885929401990530331782558043141, 0.9499516070835989810875119461809064028436, 0.9418572000538799331122753584612083652659, 0.9338317643535151384510743106138183393464, 0.9258747122872904292046909607697858626681, 0.9179854611676617518466375609653990674902, 0.9101634332720854987115840832838713554612, 0.9024080558007124218622779514513692802555, 0.8947187608344420312994997523024746481561, 0.8870949852933344058775329566907233056474, 0.8795361708953763714606266672461444022383, 0.8720417641155990268059148554652540437481, 0.8646112161455436233871237462566364157436, 0.8572439828530728308830350554160731167048, 0.8499395247425244453469447315612369857573, 0.8426973069152046221501168284377584096225, 0.8355167990302177406553164840946716839800, 0.8283974752656300322277354108287439566785, 0.8213388142799641276318029906853001579399, 0.8143402991740217040952958306017837324709, 0.8074014174530314363485930132316684297705, 0.8005216609891194797686327175999898485396, 0.7937005259840997373758528196362056425534, 0.7869375129325811858498730937766509221324, 0.7802321265853895589476145632070372895529, 0.7735838759133007097276526159890746982448, 0.7669922740710829958085504579386416555178, },
    { 1.000000000000000000000000000000000000000, 0.7604568383618460545183896873859249753475, 0.5782946030112948570545930362131434268144, 0.4397680854476881857303133336231578259493, 0.3344246478719911187527828322027724928608, 0.2543155103910080342970055083858543302085, 0.1933959689783251774319131539973439846964, 0.1470692871211828233002294902623869285186, 0.1118398451043052539124374690378746581867, 0.08504937501089856026598002345785969689094, 0.06467637882543891546556817756072387747580, 0.04918359455828632411561706836107898770425, 0.03740200081706531437355334981568317355141, 0.02844260728975267183473700260264866937793, 0.02162937521433291185350875280154002043654, 0.01644820629123368251045619881301564591324, 0.01250815095295499187138488621251445374394, 0.009511908927436864946476253160699531924110, 0.007233396189744456478161648131023810676186, 0.005500685597071693273438807825124675969776, 0.004183033977971683306471670038350398811758, 0.003181016793648522281622249338293172571527, 0.002419025973673892113793457594010940853648, 0.001839564843855234244359912809497771132576, 0.001398909665119754443995012731965930379687, 0.001063810421090797298768120396911690794771, 0.0008089819094390918283473978621390203944673, 0.0006151958251439810374839895543363501050953, 0.0004678298721623988965815688638575721914033, 0.0003557644254758444808169155363704398225966, 0.0002705434901989792929582192527080744710506, 0.0002057366471960948784546183663182928059645, },
    { 1.000000000000000000000000000000000000000, 0.0001564538402619088712753422615493598848717, 2.447780413269889735078224512008720985804E-8, 3.829646457739566105989785588606755992447E-12, 5.991628951587712183461314435723455239107E-16, 9.374133589003324437283071562544462897124E-20, 1.466619199127720628458909574032394007656E-23, 2.294582059053771218038974267927533833163E-27, 3.589961749350406706790987553377863179812E-31, 5.616633020792314645332222710264644857908E-35, 8.787438054448034835939954112296077697602E-39, 1.374828429682032112779050229478845154715E-42, 2.150971875250036652628677686695580621313E-46, 3.365278101782278104362461212648493483965E-50, 5.265106825731444425408506379787751403098E-54, 8.237461822748734749731771711361450782154E-58, 1.288782536179903234906819256928735424052E-61, 2.016349770478283712998453222332343703812E-65, 3.154656649025460159903286438614052035760E-69, 4.935581474477980619913950088312373997931E-73, 7.721906756076146364991353446502442654680E-77, 1.208121966132492313782281967679468463452E-80, 1.890153211061962317744312705074835436919E-84, 2.957217285540223765931001823632869648146E-88, 4.626680008116659240109379372702265238809E-92, 7.238618549328510447646200176448777448608E-96, 1.132509670233533294861752560334068442100E-99, 1.771854870417843101882482426208692422294E-103, 2.772134988636384669818807165401424398102E-107, 4.337111646965654912069237407317707678694E-111, 6.785577728124290751600099215097500773985E-115, 1.061629693960724289088455922591023103484E-118, },
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
  static const int64_t cdt[14][3] = {
  {0x0000020000000000LL, 0x0000000000000000LL, 0x0000000000000000LL},
  {0x0000030000000000LL, 0x0000000000000000LL, 0x0000000000000000LL},
  {0x0000032000000000LL, 0x0000000000000000LL, 0x0000000000000000LL},
  {0x0000032100000000LL, 0x0000000000000000LL, 0x0000000000000000LL},
  {0x0000032102000000LL, 0x0000000000000000LL, 0x0000000000000000LL},
  {0x0000032102010000LL, 0x0000000000000000LL, 0x0000000000000000LL},
  {0x0000032102010020LL, 0x0000000000000000LL, 0x0000000000000000LL},
  {0x0000032102010020LL, 0x0100000000000000LL, 0x0000000000000000LL},
  {0x0000032102010020LL, 0x0100020000000000LL, 0x0000000000000000LL},
  {0x0000032102010020LL, 0x0100020001000000LL, 0x0000000000000000LL},
  {0x0000032102010020LL, 0x0100020001000020LL, 0x0000000000000000LL},
  {0x0000032102010020LL, 0x0100020001000020LL, 0x0001000000000000LL},
  {0x0000032102010020LL, 0x0100020001000020LL, 0x0001000002000000LL},
  {0x0000032102010020LL, 0x0100020001000020LL, 0x0001000002000001LL},
  };

  unsigned char seed_ex[PARAM_N*8]; 
  int64_t i, j=0, x_ind;
  int64_t *buf = (int64_t*)seed_ex;
  int64_t sign, k, bitsremained, rbits, y, z;
  uint64_t r, s;
  int16_t dmsp = (int16_t)(nonce<<8);
  uint64_t t;

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
          t = buf[j++];
          if (bitsremained <= 64 - 6) {
            rbits = (rbits << 6) ^ ((r >> 58) & 63); bitsremained += 6;
          }
          r &= 0x000003FFFFFFFFFFLL;
        } while (r > 0x0000032102010020LL);  // Checking if r exceeds a maximum value. Variation is random and does not depend on private data
        y = 0;
        for (i = 0; i < 14; i++) {
          uint64_t c = t - cdt[i][2];
          uint64_t b = (((c & cdt[i][2]) & 1) + (cdt[i][2] >> 1) + (c >> 1)) >> 63;
          // Least significant bits of all cdt[i][1] are zero: overflow cannot occur at this point
          c = s - (cdt[i][1]+ b);
          b = (((c & b) & 1) + ((cdt[i][1]) >> 1) + (c >> 1)) >> 63;
          // Least significant bits of all cdt[i][0] are zero: overflow cannot occur at this point
          c = r - (cdt[i][0] + b);
          y += ~(c >> (63)) & 1LL;
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