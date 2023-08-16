from binascii import unhexlify, hexlify

from Crypto.Cipher import AES
from Crypto.Hash import SHAKE256
from Crypto.Hash import SHAKE128


VERSION = 3.1
MODE = 2
USE_AES = False

SEEDBYTES = 2*32
CRHBYTES = 2*64

Q = 8380417
N = 256
QBITS = 23
ROOT_OF_UNITY = 1753
D = 13

MONT = pow(2, 32, Q)
MONT -= Q

QINV = 58728449

if MODE == 2 :
    K = 4
    L = 4
    ETA = 2
    # pas sur si *2 
    TAU = 39
    # SETABITS = 3
    BETA = 78
    OMEGA = 80
    # only in my implemention
    POW = 17
    GAMMA1 = (1 << POW)
    GAMMA2 = (Q - 1)//88
    ALPHA = 2*GAMMA2

elif MODE == 3 :
    K = 6
    L = 5
    ETA = 4
    TAU = 49
    # SETABITS = 4
    BETA = 196
    OMEGA = 55
    POW = 19
    GAMMA1 = (1 << POW)
    GAMMA2 = (Q - 1)//32
    ALPHA = 2*GAMMA2

elif MODE == 5 :
    K = 8
    L = 7
    ETA = 2
    TAU = 60
    # SETABITS = 3
    BETA = 120
    OMEGA = 75
    POW = 19
    GAMMA1 = (1 << POW)
    GAMMA2 = (Q - 1)//32
    ALPHA = 2*GAMMA2


SHAKE128_RATE = 168
SHAKE256_RATE = 136
# what for ?
SHA3_256_RATE = 136
SHA3_512_RATE = 72

STREAM128_BLOCKBYTES = SHAKE128_RATE
STREAM256_BLOCKBYTES = SHAKE256_RATE

if USE_AES:
    # AES256CTR_BLOCKBYTES = 64
    STREAM128_BLOCKBYTES = 64
    STREAM256_BLOCKBYTES = 64

# POLT1_SIZE_PACKED = 320
POLT1_SIZE_PACKED = ((N*(QBITS - D))//8)
# POLT0_SIZE_PACKED = 416
POLT0_SIZE_PACKED = ((N*D)//8)
# POLETA_SIZE_PACKED = 96, 128, 96
# POLETA_SIZE_PACKED = ((N*SETABITS)//8)
if ETA == 2:
    POLETA_SIZE_PACKED = 96
if ETA == 4:
    POLETA_SIZE_PACKED = 128
# POLZ_SIZE_PACKED = 576K or 640K, 640K
POLZ_SIZE_PACKED = ((N*(POW +1))//8)
# POLW1_SIZE_PACKED = 128K or 192K
POLW1_SIZE_PACKED = ((N*(QBITS - POW))//8)


CRYPTO_PUBLICKEYBYTES = (SEEDBYTES//2 + K * POLT1_SIZE_PACKED)

CRYPTO_SECRETKEYBYTES = (3*SEEDBYTES//2 + (L + K)*POLETA_SIZE_PACKED + K*POLT0_SIZE_PACKED)

CRYPTO_BYTES = (SEEDBYTES//2 + L*POLZ_SIZE_PACKED + (OMEGA + K))

r = 1753

inverse_zeta_order = [
      511, 383, 447, 319, 479, 351, 415, 287, 495, 367, 431, 303, 463, 335, 399, 271, 503, 375, 439, 311, 471, 343, 407, 279,
      487, 359, 423, 295, 455, 327, 391, 263, 507, 379, 443, 315, 475, 347, 411, 283, 491, 363, 427, 299, 459, 331, 395, 267,
      499, 371, 435, 307, 467, 339, 403, 275, 483, 355, 419, 291, 451, 323, 387, 259, 509, 381, 445, 317, 477, 349, 413, 285,
      493, 365, 429, 301, 461, 333, 397, 269, 501, 373, 437, 309, 469, 341, 405, 277, 485, 357, 421, 293, 453, 325, 389, 261,
      505, 377, 441, 313, 473, 345, 409, 281, 489, 361, 425, 297, 457, 329, 393, 265, 497, 369, 433, 305, 465, 337, 401, 273,
      481, 353, 417, 289, 449, 321, 385, 257, 510, 382, 446, 318, 478, 350, 414, 286, 494, 366, 430, 302, 462, 334, 398, 270,
      502, 374, 438, 310, 470, 342, 406, 278, 486, 358, 422, 294, 454, 326, 390, 262, 506, 378, 442, 314, 474, 346, 410, 282,
      490, 362, 426, 298, 458, 330, 394, 266, 498, 370, 434, 306, 466, 338, 402, 274, 482, 354, 418, 290, 450, 322, 386, 258,
      508, 380, 444, 316, 476, 348, 412, 284, 492, 364, 428, 300, 460, 332, 396, 268, 500, 372, 436, 308, 468, 340, 404, 276,
      484, 356, 420, 292, 452, 324, 388, 260, 504, 376, 440, 312, 472, 344, 408, 280, 488, 360, 424, 296, 456, 328, 392, 264,
      496, 368, 432, 304, 464, 336, 400, 272, 480, 352, 416, 288, 448, 320, 384
]


zetas_inv = [-1976782, 846154, -1400424, -3937738, 1362209, 48306, -3919660, 554416, 3545687, -1612842, 976891, -183443, 2286327, 420899, 2235985, 2939036, 3833893, 
            260646, 1104333, 1667432, -1910376, 1803090, -1723600, 426683, -472078, -1717735, 975884, -2213111, -269760, -3866901, -3523897, 3038916, 1799107, 3694233, -1652634, 
            -810149, -3014001, -1616392, -162844, 3183426, 1207385, -185531, -3369112, -1957272, 164721, -2454455, -2432395, 2013608, 3776993, -594136, 3724270, 2584293, 1846953, 
            1671176, 2831860, 542412, -3406031, -2235880, -777191, -1500165, 1374803, 2546312, -1917081, 1279661, 1962642, -3306115, -1312455, 451100, 1430225, 3318210, -1237275, 
            1333058, 1050970, -1903435, -1869119, 2994039, 3548272, -2635921, -1250494, 3767016, -1595974, -2486353, -1247620, -4055324, -1265009, 2590150, -2691481, -2842341, 
            -203044, -1735879, 3342277, -3437287, -4108315, 2437823, -286988, -342297, 3595838, 768622, 525098, 3556995, -3207046, -2031748, 3122442, 655327, 522500, 43260, 1613174, 
            -495491, -819034, -909542, -1859098, -900702, 3193378, 1197226, 3759364, 3520352, -3513181, 1235728, -2434439, -266997, 3562462, 2446433, -2244091, 3342478, -3817976, 
            -2316500, -3407706, -2091667, -3839961, 3628969, 3881060, 3019102, 1439742, 812732, 1584928, -1285669, -1341330, -1315589, 177440, 2409325, 1851402, -3159746, 3553272, 
            -189548, 1316856, -759969, 210977, -2389356, 3249728, -1653064, 8578, 3724342, -3958618, -904516, 1100098, -44288, -3097992, -508951, -264944, 3343383, 1430430, -1852771, 
            -1349076, 381987, 1308169, 22981, 1228525, 671102, 2477047, 411027, 3693493, 2967645, -2715295, -2147896, 983419, -3412210, -126922, 3632928, 3157330, 3190144, 1000202, 
            4083598, -1939314, 1257611, 1585221, -2176455, -3475950, 1452451, 3041255, 3677745, 1528703, 3930395, 2797779, -2071892, 2556880, -3900724, -3881043, -954230, -531354, 
            -811944, -3699596, 1600420, 2140649, -3507263, 3821735, -3505694, 1643818, 1699267, 539299, -2348700, 300467, -3539968, 2867647, -3574422, 3043716, 3861115, -3915439, 
            2537516, 3592148, 1661693, -3530437, -3077325, -95776, -2706023, -280005, -4010497, 19422, -1757237, 3277672, 1399561, 3859737, 2118186, 2108549, -2619752, 1119584, 549488, 
            -3585928, 1079900, -1024112, -2725464, -2680103, -3111497, 2884855, -3119733, 2091905, 359251, -2353451, -1826347, -466468, 876248, 777960, -237124, 518909, 2608894, -25847
            ]



def montgomery_reduce(a):
    """
    *************************************************
    * Description: For finite field element a with 0 <= a <= Q*2^32,
    *              compute r \equiv a*2^{-32} (mod Q) such that 0 <= r < 2*Q.
    *
    * Arguments:   - int a: finite field element
    *
    * Returns:     - int r: such as in the Description.
    **************************************************
    """
    t   = (a * QINV) & 0xFFFFFFFF
    t  *= Q
    t   = a - t
    t >>= 32
    return t



def reduce32(a):
    """
    *************************************************
    * Description: For finite field element a, compute r \equiv a (mod Q)
    *              such that 0 <= r < 2*Q.
    *
    * Arguments:   - int a: finite field element
    *
    * Returns:     - int r: such as in the Description.
    **************************************************
    """
    MAX_VAL = 2**31 - 2**22 - 1
    MIN_VAL = -2**31 + 2**22
    t = (a + (1 << 22)) >> 23  # Calculate t as floor((a + 2^22) / 2^23)
    t = a - t * Q  # Calculate t as a - t * Q
    t = ((t + Q) & MAX_VAL) - Q if t > MAX_VAL else t  # Check if t is greater than the maximum value, if so, subtract Q, else if t is less than the minimum value, add Q   
    return t


def poly_reduce(a):
    """
    *************************************************
    * Description: Inplace reduction of all coefficients of
    *              input polynomial to representative in [0,2*Q[.
    *
    * Arguments:   - array[N](int) a: input/output polynomial
    **************************************************
    """
    for i in range(N):
        a[i] = reduce32(a[i])



def invntt_frominvmont(p):
    """
    *************************************************
    * Description: backward NTT, in-place. No modular reduction is performed after
    *              additions or subtractions. Hence output coefficients can be up
    *              to 16*Q larger than the coefficients of the input polynomial.
    *              Output vector is in bitreversed order.
    *              Elements of p must be at least 32 bits long or else everflow occurs.
    *
    * Arguments:   - array[N](int) p: input/output coefficient array
    **************************************************
    """
    f = 41978
    j = 0
    j_ = 0
    k = 0
    start = 0
    
    stage = 0
    
    for len_ in (2**p for p in range(0, 8)):
        while(start<N):
            index1 = inverse_zeta_order[k]
            zeta1 = zetas_inv[k]

            for j in range(start, start + len_):
                t = p[j]
                p[j] =  (t + p[j + len_])
                p[j + len_] = t - p[j + len_]
                p[j + len_] = montgomery_reduce(int(zeta1 * p[j + len_]))   
                
            k += 1
            j_ = j + 1
            start = ( j_ + len_)
        stage += 1
        start = 0
        
    for j in range(N):
        p[j] = montgomery_reduce(int(f * p[j]))


def polyt1_unpack(a):
    """
    *************************************************
    * Description: Unpack polynomial t1 with 9-bit coefficients.
    *              Output coefficients are standard representatives.
    *
    * Arguments:   - bytes[POLT1_SIZE_PACKED] a: byte array with bit-packed polynomial
    *
    * Returns      - array[N](int) r: output polynomial
    **************************************************
    """
    r = [0]*N
    for i in range(N//4):
        r[4*i+0] = ((a[5*i+0] >> 0) | (a[5*i+1] << 8)) & 0x3FF
        r[4*i+1] = ((a[5*i+1] >> 2) | (a[5*i+2] << 6)) & 0x3FF
        r[4*i+2] = ((a[5*i+2] >> 4) | (a[5*i+3] << 4)) & 0x3FF
        r[4*i+3] = ((a[5*i+3] >> 6) | (a[5*i+4] << 2)) & 0x3FF
    return r


def unpack_pk(pk):
    """
    *************************************************
    * Description: Unpack public key pk = (rho, t1).
    *
    * Arguments:   - str(hex) pk: string of hex values containing bit-packed pk
    *
    * Returns:     - bytes[SEEDBYTES] rho: output byte array for rho
    *              - array[K][N](int) t1: output vector t1
    **************************************************
    """
    offset = 0
    # rho
    rho = unhexlify(pk[:SEEDBYTES])
    offset = SEEDBYTES

    # t1
    t1 = [ polyt1_unpack(unhexlify(pk[offset + index : offset + index + POLT1_SIZE_PACKED*2])) for index in range(0, (POLT1_SIZE_PACKED*2)*K, (POLT1_SIZE_PACKED*2))]

    return rho, t1


def polyz_unpack(a):
    """
    *************************************************
    * Description: Unpack polynomial z with coefficients
    *              in [-(GAMMA1 - 1), GAMMA1 - 1].
    *              Output coefficients are standard representatives.
    *
    * Arguments:   - bytes[POLZ_SIZE_PACKED] a: byte array with bit-packed polynomial
    *
    * Returns:     - array[N](int) r: output polynomial
    **************************************************
    """
    r = [0]*N
    if GAMMA1 == ( 1 << 17 ):
        for i in range(N//4):
            r[4*i+0]  = (a[9*i+0] | a[9*i+1] << 8 | a[9*i+2] << 16) & 0x3FFFF
            r[4*i+1]  = (a[9*i+2] >> 2 | a[9*i+3] << 6 | a[9*i+4] << 14) & 0x3FFFF
            r[4*i+2]  = (a[9*i+4] >> 4 | a[9*i+5] << 4 | a[9*i+6] << 12) & 0x3FFFF
            r[4*i+3]  = (a[9*i+6] >> 6 | a[9*i+7] << 2 | a[9*i+8] << 10) & 0x3FFFF

            r[4*i+0] = GAMMA1 - r[4*i+0]
            r[4*i+1] = GAMMA1 - r[4*i+1]
            r[4*i+2] = GAMMA1 - r[4*i+2]
            r[4*i+3] = GAMMA1 - r[4*i+3]


    elif GAMMA1 == ( 1 << 19 ):
        for i in range(N//2):
            r[2*i+0]  = a[5*i+0]
            r[2*i+0] |= a[5*i+1] << 8
            r[2*i+0] |= a[5*i+2] << 16
            r[2*i+0] &= 0xFFFFF

            r[2*i+1]  = a[5*i+2] >> 4
            r[2*i+1] |= a[5*i+3] << 4
            r[2*i+1] |= a[5*i+4] << 12
            r[2*i+0] &= 0xFFFFF

            r[2*i+0] = GAMMA1 - r[2*i+0]
            r[2*i+1] = GAMMA1 - r[2*i+1]

    return r



def unpack_sig(z, h, seed, sig):
    """
    *************************************************
    * Description: Unpack signature sig = (z, h, c).
    *
    * Arguments:   - array[0] z: declared array of output vector z
    *              - array[K][N](int) h: allocated array with zeros to output hint vector h
    *              - bytearray[0] seed: allocated array with zeros to output challenge polynomial
    *              - str[] sig: ascii str encoding hex value of signature
    *                size can be equal to 2*CRYPTO_BYTES if the message was not returned with the signature
    *                else it is 2*CRYPTO_BYTES + len(msg)
    *
    * Returns:     - 1 in case of malformed signature; otherwise 0.
    **************************************************
    """

    offset = 0

    # Decode seed to expand c
    seed += sig[:SEEDBYTES].encode()
    offset += SEEDBYTES

    # z
    [ z.append(polyz_unpack(unhexlify(sig[offset + index : offset + index + POLZ_SIZE_PACKED*2]))) for index in range(0, (POLZ_SIZE_PACKED*2)*L, (POLZ_SIZE_PACKED*2)) ]
    offset += (POLZ_SIZE_PACKED*2)*L

    # Decode h
    k = 0
    for i in range(K):
        h_ = [0]*N
        # for j in range(N):
        #     h[i][j] = 0

        h_index = int(sig[offset + 2*OMEGA + 2*i: offset + 2*OMEGA + 2*(i+1) ], 16)
        if( h_index < k or h_index > OMEGA):
            return 1

        for j in range(k, h_index):
            # Coefficients are ordered for strong unforgeability
            if(j > k and int(sig[offset + 2*j: offset + 2*(j + 1)], 16) <= int(sig[offset + 2*(j-1): offset + 2*j], 16)):
                return 1
            #h[i][int(sig[offset + 2*j : offset + 2*(j + 1)], 16)] = 1
            h_[int(sig[offset + 2*j : offset + 2*(j + 1)], 16)] = 1

        h[i] = h_
        k = h_index

    # Extra indices are zero for strong unforgeability
    for j in range(k, OMEGA):
        if ( int(sig[offset + 2*j: offset + 2*(j + 1)], 16) ):
            return 1

    offset += (2*(OMEGA + K))
    return 0


def poly_chknorm(a,  bound) :
    """
    *************************************************
    * Description: Check infinity norm of polynomial against given bound.
    *              Assumes input coefficients to be standard representatives.
    *
    * Arguments:   - array[N](int) a: polynomial
    *              - int bound: norm bound
    *
    * Returns:     - 0 if norm is strictly smaller than bound and 1 otherwise.
    **************************************************
    """
    if bound > (Q-1)//8:
        return 1
    # It is ok to leak which coefficient violates the bound since
    # the probability for each coefficient is independent of secret
    # data but we must not leak the sign of the centralized representative.
    for i in range(N):
        # Absolute value
        t = (a[i] >> 31)
        t = a[i] - (t &( 2*(a[i])))
        # t = a[i] - (t & 2 * a[i])

        if (t >= bound):
            return 1

        return 0


def polyvecl_chknorm(v, bound):
    """
    *************************************************
    * Description: Check infinity norm of polynomials in vector of length L.
    *              Assumes input coefficients to be standard representatives.
    *
    * Arguments:   - array[L][N](int)v: pointer to vector of polynomials
    *              - int bound: norm bound
    *
    * Returns:     - 0 if norm of all polynomials are strictly smaller than bound and 1
    *                otherwise.
    **************************************************
    """
    for i in range(L):
        if (poly_chknorm(v[i], bound)):
            return 1
    return 0


def challenge(seed):
    """
    *************************************************
    * Description: Implementation of H. Samples polynomial with 60 nonzero
    *              coefficients in {-1,1} using the output stream of
    *              SHAKE256(mu|w1).
    *
    * Arguments:   - str(hex) mu: stirng containing mu encoded as a string oh hex values
    *              - array[K][N](int) w1: vector w1
    *
    * Returns:     - array[N](int) c: output challenge polynomial
    **************************************************
    """
    c = [0]*N
    shake = SHAKE256.new(seed)
    outbuf = shake.read(SHAKE256_RATE)

    signs = 0
    for i in range(8):
        signs |= outbuf[i] << 8*i
    pos = 8

    for i in range(N):
        c[i] = 0

    for i in range(N- TAU, N):

        while True:
            if(pos >= SHAKE256_RATE):
                outbuf += shake.read(SHAKE256_RATE)
                pos= 0
            b = outbuf[pos]
            pos += 1

            if b<= i:
                break

        c[i] = c[b]

        c[b] = 1 - 2*(signs & 1)
        signs >>= 1
    return c


def rej_uniform(buf, buflen, len_ = N):
    """
    *************************************************
    * Description: Sample uniformly random coefficients in [0, Q-1] by
    *              performing rejection sampling using array of random bytes.
    *
    * Arguments:   - array[len_](int) A: output array (declared outside)
    *              - unsigned int len_: number of coefficients to be sampled (default: N)
    *              - str[buflen] buf: array of random bytes
    *              - int buflen: length of array of random bytes
    *
    * Returns:     - int ctr: number of sampled coefficients. Can be smaller than len_ if not enough
    *                random bytes were given.
    **************************************************
    """
    A_ = []
    ctr, pos = 0, 0
    while(ctr < len_ and pos + 3 <= buflen):
        t  = buf[pos]
        pos+= 1
        t |= (buf[pos] << 8)
        pos+=1
        t |= (buf[pos] << 16)
        pos+= 1
        t &= 0x7FFFFF

        if(t < Q):
            A_.append(t)
            ctr+=1
    return ctr, A_


def poly_uniform(seed, nonce):
    """
    *************************************************
    * Description: Sample polynomial with uniformly random coefficients
    *              in [-ETA,ETA] by performing rejection sampling using the
    *              output stream from SHAKE256(seed|nonce).
    *
    * Arguments:   - bytes[SEEDBYTES] seed: byte array with seed
    *              - int nonce: 2-byte nonce
    *
    * Returns:     - array[N](int) S: output polynomial
    **************************************************
    """
    ctr = 0
    # /!\ maybe change with ((768 + STREAM128_BLOCKBYTES - 1)//STREAM128_BLOCKBYTES)
    # nblocks = (769 + STREAM128_BLOCKBYTES)//STREAM128_BLOCKBYTES
    nblocks = ((768 + STREAM128_BLOCKBYTES - 1)//STREAM128_BLOCKBYTES)

    buflen = nblocks*STREAM128_BLOCKBYTES
    
    if USE_AES == True:
        # nonce fits over 34 bytes, we declare the first 12 here
        m = bytearray(12)
        # counters for aes in counter mode
        CPT = [0, 1, 2, 3]
        m[1] = nonce >> 8
        m[0] = nonce ^ (m[1]<<8)

        msg = bytes(m)

        # initialise aes ctr 0
        aes = AES.new(seed, AES.MODE_ECB)

    else:
        m = bytearray(34)
        for i in range(32):
            m[i] = seed[i]
            
        m[33] = nonce >> 8
        m[32] = nonce ^ (m[33]<<8 )


        # initialise shake
        shake = SHAKE128.new(m)

    S = []
    out = b""
    
    # First Squeeze Block
    while (nblocks > 0):
        if USE_AES == True:
            for i in range(len(CPT)):
                out+= aes.encrypt(msg + int.to_bytes(CPT[i], length = 4, byteorder= 'big'))
                # next 4 counters
                CPT[i]+=4
        else:
            out+= shake.read(SHAKE128_RATE)
        nblocks -= 1

    ctr, S = rej_uniform(out, buflen)

    # if not enough random bytes to fill the polynomial coefficients
    out = bytearray(out)
    
    while(ctr < N):
        off = buflen % 3
        for i in range(off):
            out[i] = out[buflen - off + i]

        buflen = STREAM128_BLOCKBYTES + off
        nblocks = 1
        # while (nblocks > 0):
        #     for i in range(len(CPT)):
        #         if USE_AES == True:
        #             tempp = aes.encrypt(msg + int.to_bytes(CPT[i], length = 4, byteorder= 'big'))
        #             # print("out2temp: ", hexlify(tempp))
        #             out[off:] = tempp
        #             CPT[i]+=4
        #         else:
        #             out[off:] = shake.read(SHAKE128_RATE)
        #     nblocks -= 1
        while (nblocks > 0):
            if USE_AES == True:
                tempp = b''
                for i in range(len(CPT)):
                    tempp += aes.encrypt(msg + int.to_bytes(CPT[i], length = 4, byteorder= 'big'))
                    out = tempp
                    CPT[i]+=4

                out = tempp + out[len(tempp):]
            else:
                out[off:] = shake.read(SHAKE128_RATE)
            nblocks -= 1

        ctr_, a = rej_uniform(out, buflen, len_ = N - ctr)
        ctr += ctr_
        S += a
    return S


def polyvec_matrix_expand(rho):
    """
    **************************************************
    * Description: Implementation of ExpandA. Generates matrix A with uniformly
    *              random coefficients a_{i,j} by performing rejection
    *              sampling on the output stream of SHAKE128(rho|i|j).
    *              warning: C version uses poly_uniform function not implemented here (maybe code it ?)
    *
    * Arguments:   - str rho: byte array containing seed rho
    *
    * Returns:     - array[K][L][N](int) A: output matrix
    **************************************************
    """
    A = []
    for i in range(K):
        A_ = []
        for j in range(L):
            A_.append(poly_uniform(rho,  (i << 8) + j))
        A.append(A_)
    return A


def polyeta_unpack(a):
    """
    *************************************************
    * Description: Unpack polynomial with coefficients in [-ETA,ETA].
    *              Output coefficients lie in [Q-ETA,Q+ETA].
    *
    * Arguments:   - bytes[POLETA_SIZE_PACKED] a: byte array with bit-packed polynomial
    *
    * Returns:     - array[N](int) r: output polynomial
    **************************************************
    """
    r = [0]*N
    if ETA == 2:
        for i in range(N//8):
            r[8*i+0] = a[3*i+0] & 0x07
            r[8*i+1] = (a[3*i+0] >> 3) & 0x07
            r[8*i+2] = ((a[3*i+0] >> 6) | (a[3*i+1] << 2)) & 0x07
            r[8*i+3] = (a[3*i+1] >> 1) & 0x07
            r[8*i+4] = (a[3*i+1] >> 4) & 0x07
            r[8*i+5] = ((a[3*i+1] >> 7) | (a[3*i+2] << 1)) & 0x07
            r[8*i+6] = (a[3*i+2] >> 2) & 0x07
            r[8*i+7] = (a[3*i+2] >> 5) & 0x07

            r[8*i+0] = ETA - r[8*i+0]
            r[8*i+1] = ETA - r[8*i+1]
            r[8*i+2] = ETA - r[8*i+2]
            r[8*i+3] = ETA - r[8*i+3]
            r[8*i+4] = ETA - r[8*i+4]
            r[8*i+5] = ETA - r[8*i+5]
            r[8*i+6] = ETA - r[8*i+6]
            r[8*i+7] = ETA - r[8*i+7]

    else:
        for i  in range(N//2):
            r[2*i+0] = a[i] & 0x0F
            r[2*i+1] = a[i] >> 4
            r[2*i+0] = ETA - r[2*i+0]
            r[2*i+1] = ETA - r[2*i+1]

    return r



def polyt0_unpack(a):
    """
    *************************************************
    * Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
    *              Output coefficients lie in ]Q-2^{D-1},Q+2^{D-1}].
    *
    * Arguments:   - bytes[POLT0_SIZE_PACKED] a: byte array with bit-packed polynomial
    *
    * Returns:     - array[N](int) r: output polynomial
    **************************************************
    """
    r = [0]*N
    for i in range(N//8):
        r[8*i+0]  = a[13*i+0]
        r[8*i+0] |= a[13*i+1] << 8
        r[8*i+0] &= 0x1FFF

        r[8*i+1]  = a[13*i+1] >> 5
        r[8*i+1] |= a[13*i+2] << 3
        r[8*i+1] |= a[13*i+3] << 11
        r[8*i+1] &= 0x1FFF

        r[8*i+2]  = a[13*i+3] >> 2
        r[8*i+2] |= a[13*i+4] << 6
        r[8*i+2] &= 0x1FFF

        r[8*i+3]  = a[13*i+4] >> 7
        r[8*i+3] |= a[13*i+5] << 1
        r[8*i+3] |= a[13*i+6] << 9
        r[8*i+3] &= 0x1FFF

        r[8*i+4]  = a[13*i+6] >> 4
        r[8*i+4] |= a[13*i+7] << 4
        r[8*i+4] |= a[13*i+8] << 12
        r[8*i+4] &= 0x1FFF

        r[8*i+5]  = a[13*i+8] >> 1
        r[8*i+5] |= a[13*i+9] << 7
        r[8*i+5] &= 0x1FFF

        r[8*i+6]  = a[13*i+9] >> 6
        r[8*i+6] |= a[13*i+10] << 2
        r[8*i+6] |= a[13*i+11] << 10
        r[8*i+6] &= 0x1FFF

        r[8*i+7]  = a[13*i+11] >> 3
        r[8*i+7] |= a[13*i+12] << 5
        r[8*i+7] &= 0x1FFF


        r[8*i+0] =  (1 << (D-1)) - r[8*i+0]
        r[8*i+1] =  (1 << (D-1)) - r[8*i+1]
        r[8*i+2] =  (1 << (D-1)) - r[8*i+2]
        r[8*i+3] =  (1 << (D-1)) - r[8*i+3]
        r[8*i+4] =  (1 << (D-1)) - r[8*i+4]
        r[8*i+5] =  (1 << (D-1)) - r[8*i+5]
        r[8*i+6] =  (1 << (D-1)) - r[8*i+6]
        r[8*i+7] =  (1 << (D-1)) - r[8*i+7]

    return r

def unpack_sk(sk):
    """
    *************************************************
    * Description: Unpack secret key sk = (rho, key, tr, s1, s2, t0).
    *
    * Arguments:   - str(hex) sk: input byte array
    *
    * Returns:     - bytes[SEEDBYTES] rho: output byte array for rho
    *              - str(hex) key: string of hex values containing key
    *              - str(hex) tr: string of hex values containing tr
    *              - array[L][N](int) s1: vector s1
    *              - array[K][N](int) s2: vector s2
    *              - array[K][N](int) t0: vector t1
    **************************************************
    """
    offset = 0
    # rho
    rho = unhexlify(sk[:SEEDBYTES])
    offset = SEEDBYTES

    # key
    key = sk[offset : offset + SEEDBYTES]
    offset += SEEDBYTES

    # tr
    tr = sk[offset : offset + SEEDBYTES]
    offset += SEEDBYTES


    # s1
    s1 = [ polyeta_unpack(unhexlify(sk[offset + index : offset + index + POLETA_SIZE_PACKED*2])) for index in range(0, (POLETA_SIZE_PACKED*2)*L, (POLETA_SIZE_PACKED*2))]
    offset += (POLETA_SIZE_PACKED*2)*L

    # s2
    s2 = [ polyeta_unpack(unhexlify(sk[offset + index : offset + index + POLETA_SIZE_PACKED*2])) for index in range(0, (POLETA_SIZE_PACKED*2)*K, (POLETA_SIZE_PACKED*2))]
    offset += (POLETA_SIZE_PACKED*2)*K

    # t0
    t0 = [ polyt0_unpack(unhexlify(sk[offset + index : offset + index + POLT0_SIZE_PACKED*2])) for index in range(0, (POLT0_SIZE_PACKED*2)*K, (POLT0_SIZE_PACKED*2))]

    return rho, key, tr, s1, s2, t0


def decompose(a):
    """
    *************************************************
    * Description: For finite field element a, compute high and low bits a0, a1 such that
    *              a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except if
    *              a1 = (Q-1)/ALPHA where we set a1 = 0 and -ALPHA/2 <= a0 = a mod^+ Q - Q < 0.
    *              Assumes a to be standard representative.
    *
    * Arguments:   - int a: input element
    *
    * Returns:     - int a: output element a1
                   - int a0: output element Q + a0
    **************************************************
    """
    a = int(a)
    a1  = int((a + 127) >> 7)
    if GAMMA2 == (Q-1)//32:
        a1  = (a1*1025 + (1 << 21)) >> 22
        a1 &= 15
    elif GAMMA2 == (Q-1)//88:
        a1  = (a1*11275 + (1 << 23)) >> 24
        a1 ^= ((43 - a1) >> 31) & a1
    a0 = a - a1*ALPHA
    a0 -= (((Q-1)//2 - a0) >> 31) & Q
    return a1, a0


def use_hint(a, hint):
    """
    *************************************************
    * Description: Correct high bits according to hint.
    *
    * Arguments:   - int a: input element
    *              - int hint: hint bit
    *
    * Returns:     - corrected high bits.
    **************************************************
    """
    a1, a0 = decompose(a)
    if(hint == 0):
        return a1
    elif (a0 > 0):
        return (a1 + 1) & 0xF
    else:
        return (a1 - 1) & 0xF


def use_hint(a, hint):
    """
    *************************************************
    * Description: Correct high bits according to hint.
    *
    * Arguments:   - int a: input element
    *              - int hint: hint bit
    *
    * Returns:     - corrected high bits.
    **************************************************
    """
    border = 0
    
    a1, a0 = decompose(a)
    if(hint == 0):
        return a1
    
    if GAMMA2 == (Q-1)//32:
        if (a0 > border):
            return (a1 + 1) & 0xF
        else:
            return (a1 - 1) & 0xF
    elif GAMMA2 == (Q-1)//88:
        if(a0 > border):
            # return (a1 == 43) ?  0 : a1 + 1
            return 0 if a1 == 43 else a1 + 1
        else:
            # return (a1 ==  0) ? 43 : a1 - 1
            return 43 if a1 == 0 else a1 - 1


def poly_use_hint(b, h):
    """
    *************************************************
    * Description: Use hint polynomial to correct the high bits of a polynomial.
    *
    * Arguments:   - array[N](int) b: input polynomial
    *              - array[N](int) h: input hint polynomial
    *
    * Returns:      - array[N](int) a: output polynomial with corrected high bits
    **************************************************
    """
    a = [0]*N
    for i in range(N):
        a[i] = use_hint(b[i], h[i])
    return a


def polyveck_use_hint(u, H):
    """
    *************************************************
    * Description: Use hint vector to correct the high bits of input vector.
    *
    * Arguments:   - array[K][N](int) u: input vector
    *              - array[K][N](int) H: input hint vector
    *
    * Returns:     - array[K][N](int) w: output vector of polynomials with corrected high bits
    **************************************************
    """
    w = []
    for i in range(K):
        w.append(poly_use_hint(u[i], H[i]))
    return w