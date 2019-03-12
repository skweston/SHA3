/*
 * 
 */

/**
 * 
 * @author James Haines-Temons, Shannon Weston additional credits to Paulo Baretto and Markku-Juhani O. Saarinen for c implimentations and advice
 *
 */

public class sha3 {
	
	private static boolean cshake256 = false, kmac = false;
	
	/** Defined number of transform rounds. */
	private static final int KECCAKF_ROUNDS = 24;
	
	/**NIST defined constants. */
	private static int[] rotc = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2,  14, 27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};
	
	/**NIST defined constants. */
	private static int[] piln = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};
	
	/** Becomes the working array of constants.*/
	private static Long keccak_consts[] = {0x0000000000000001L, 
            0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
            0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 
            0x8000000000008009L, 0x000000000000008aL, 0x0000000000000088L,
            0x0000000080008009L, 0x000000008000000aL, 0x000000008000808bL,
            0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L, 
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL,
            0x800000008000000aL, 0x8000000080008081L, 0x8000000000008080L, 
            0x0000000080000001L, 0x8000000080008008L};
	
	
	public sha3() {
		super();
	}
	
	private static int sha3_update(sha3_ctx_t c, byte[] data, int len) {

		int i, j;

	    j = c.pt;
	    System.out.println(j);
	    for (i = 0; i < len; i++) {
	    	
	        if (i < data.length) c.st_b[j++] ^= data[i];
	        else if (cshake256) c.st_b[j++] ^= 0; //need to add this for cshake because bytepad doesn't return full length 136.
	        if (j >= c.rsiz) {
	        	c.update_q();
	        	keccak(c.st_q);
	        	c.update_b();
	            j = 0;
	        }
	    }
	    c.pt = j;

	    return 1;
	}
	
	private static void sha3_final(byte[] md, sha3_ctx_t c)
	{
	    int i;

	    c.st_b[c.pt] ^= 0x06L;
	    c.st_b[c.rsiz - 1] ^= 0x80L;
	    
	    c.update_q();
	    keccak(c.st_q);
	    c.update_b();

	    for (i = 0; i < md.length; i++) {
	    	md[i] = c.st_b[i]; 
	    }
	}
	
	
	/*right_encode(x):
		Validity Conditions: 0 ≤ x < 2 2040
		1. Let n be the smallest positive integer for which 2^8n > x.
		2. Let x 1 , x 2 ,..., x n be the base-256 encoding of x satisfying:
		x = ∑ 2 8(n-i) x i , for i = 1 to n.
		3. Let O i = enc 8 (x i ), for i = 1 to n.
		4. Let O n+1 = enc 8 (n).
		5. Return O = O 1 || O 2 || ... || O n || O n+1 .*/
	private static byte[] right_encode(int x) {
		int n =1, i;
		int temp = x;
		while (1 << 8*n < x) {
			n++;
		}
		byte[] O = new byte[n+1];
		for (i=1; i < n; i++) {
			O[n - 1 - i] = (byte) (temp & 0xFF);
			temp >>>= 8;
		}
		O[O.length-1] = (byte) n;
		
		return O;
	}
	
	
	/*left_encode(x):
		Validity Conditions: 0 ≤ x < 2 2040
		1. Let n be the smallest positive integer for which 2 8n > x.
		2. Let x 1 , x 2 , ..., x n be the base-256 encoding of x satisfying:
		x = ∑ 2 8(n-i) x i , for i = 1 to n.
		3. Let O i = enc 8 (x i ), for i = 1 to n.
		4. Let O 0 = enc 8 (n).
		5. Return O = O 0 || O 1 || ... || O n−1 || O n .*/
	private static byte[] left_encode(int x) {
		
		int n = 1, i;
		int temp = x;
		while (1 << (8*n) <= x) n++;
		byte[] O = new byte[n+1];
		O[0] = (byte) n;
		for (i=n; i > 0; i--) {
			O[i] = (byte) (temp & 0xFF);
			temp >>>= 8;
		}
			
		return O;
	}
	
	
	private static byte[] encode_string(byte[] S) {
		
		return concat(left_encode(S.length * 8), S);
		
	}
	
	
	/*bytepad(X, w):
		Validity Conditions: w > 0
		1. z = left_encode(w) || X.
		2. while len(z) mod 8 ≠ 0: (byte arrays always multiple of 8 bits)
			z = z || 0
		3. while (len(z)/8) mod w ≠ 0:
			z = z || 00000000
		4. return z.*/
	private static byte[] bytepad(byte[] X, int w) {
		
		
		byte[] w_encode = left_encode(w);
		byte[] z = concat(w_encode, X);
		byte[] result = new byte[w*((w_encode.length + X.length + w -1)/w)]; 
				
		for (int i = 0; i< z.length; i++) {
			if (i < result.length) {
				result[i] = z[i];
			} else {
				result[i] = (byte) 0;
			}
		}
		return z;
	}
	
	//concatenates two byte arrays
	private static byte[] concat(byte[] a, byte[] b) {
		
		int i, j;
		byte[] result = new byte[a.length + b.length];
		for (i=0; i < a.length; i++) {
			result[i] = a[i];
		}
		for (j = 0; j < b.length; j++) {
			result[i+j] = b[j];
		}
		return result;
	}
	
	private static void shake_out(sha3_ctx_t c, byte[] md, int len) {
	    
	    int i, j;

	    j = c.pt;
	    for (i = 0; i < len; i++) {
	        if (j >= c.rsiz) {
	        	c.update_q();
	            keccak(c.st_q);
	            c.update_b();
	            j = 0;
	        }
	        md[i] = c.st_b[j++];
	    }
	    c.pt = j;
	}
		
	public static byte[] sha3(String in, int inlen, byte[] md, int mdlen)
	{
		
	    sha3_ctx_t sha3 = new sha3_ctx_t();
	    sha3.mdlen = mdlen;
	    sha3.rsiz = 200 - (2*mdlen);
	    byte[] in_as_bytes = in.getBytes();
	    sha3_update(sha3, in_as_bytes, in_as_bytes.length);
	    sha3_final(md, sha3);

	    return md;
	}

	
	public static byte[] cSHAKE256(byte[] X, int L, String N, String S) {
		if (N.length() > 0 || S.length() > 0)   cshake256 = true;
		byte[] result = new byte[64]; 
		sha3_ctx_t sponge = new sha3_ctx_t();

		sponge.mdlen = 32;
		sponge.rsiz = 136;

		/*This ridiculous line of code loses any trailing zeros in the array it builds*/
		byte[] bytepad_ns = bytepad( concat(encode_string(N.getBytes()),encode_string(S.getBytes())), 136 );
		
		sha3_update( sponge, bytepad_ns, 136 );
		sha3_update( sponge, X, X.length );
		
		
//		if (kmac) sha3_update(sponge, right_encode(0), 2 /*length of right_encode(0)*/);
		
		
		if (cshake256) 	sponge.st_b[sponge.pt] ^= 0x04; 
		else sponge.st_b[sponge.pt] ^= 0x1F;
		sponge.st_b[sponge.rsiz - 1] ^= (byte)0x80;
		sponge.update_q();
		keccak(sponge.st_q);
		sponge.update_b();
		sponge.pt = 0;
		shake_out(sponge, result, result.length);

		return result;

	}

	public static byte[] KMACXOF256(byte[] K, byte[] X, int L, String S) {
		kmac = true;
		byte[] bp_k = new byte[136];
		byte[] result = new byte[64];
		/*
		newX = bytepad(encode_string(K), 136) || X || right_encode(0).
		return cSHAKE256(newX, L, “KMAC”, S).
		*/
		byte[] encode_K = bytepad(encode_string(K), 136);
		for (int i = 0; i < encode_K.length; i++) {
			bp_k[i] = encode_K[i];
		}
		byte[] concat1 = concat(bp_k, X);
		byte[] newX = concat(concat1, right_encode(0));
		result = cSHAKE256(newX, L, "KMAC", S);
		
		/* Test print for kmacxof256 input manipulations. */
		for (byte b : X) {
			System.out.printf("%x ", b);
		}
		System.out.println(bp_k.length);
		
		
		return result;
	}
	
	private static long ROTL(long x, int y) {
		return (x << y) | (x >>> (64 - y));
	}
	
	private static long endian_conversion(long in) {
		return ((long) (in & 0xFF00000000000000L) >>> 56) | ((long) (in & 0x00FF000000000000L) >>> 40) |
				((long) (in & 0x0000FF0000000000L) >>> 24) |((long) (in & 0x000000FF00000000L) >>> 8) |
				((long) (in & 0x00000000FF000000L) << 8) |((long) (in & 0x0000000000FF0000L) << 24) |
				((long) (in & 0x000000000000FF00L) << 40) |((long) (in & 0x00000000000000FFL) << 56);
							 
	}
	
	private static long[] keccak(long st[]) {
		
		long t;
		int j, i, r;
		long bc[] = new long[5];

		   
		for (int k=0; k < st.length; k++) {
		    st[k] = endian_conversion(st[k]);
		}
		System.out.println();

		//Actual iteration
		for(r = 0; r < KECCAKF_ROUNDS; r++) {


			//Theta
			for(i = 0; i < 5; i++) {
					bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
			}

			for(i = 0; i < 5; i++) {
					t = bc[(i + 4) % 5] ^ ROTL(bc[(i + 1) % 5], 1);
					for(j = 0; j < 25; j += 5) {
						st[j + i] ^= t;
					}
			}

		   
		    //Rho Pi
		    t = st[1];
		    for(i = 0; i <  KECCAKF_ROUNDS; i++) {
		    	j = piln[i];
		    	bc[0] = st[j];
		    	st[j] = ROTL(t, rotc[i]);
		    	t = bc[0];
			}

		   
			//Chi
			for(j = 0; j < 25; j += 5) {
	
				for(i = 0; i <  5; i++) {
					bc[i] = st[j + i];
				}
				for(i = 0; i <  5; i++) {
					st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
				}
			}

		   
		    //Iota
		    st[0] ^= keccak_consts[r];

		}

		System.out.println("End Keccak: ");

		for (int k=0; k < st.length; k++) {
		    st[k] = endian_conversion(st[k]);
		    }

		for (int k=0; k < st.length; k++) {
			System.out.printf("%x ", st[k]);
		}
		System.out.println();

		return st;
}
	
    private static class sha3_ctx_t {
        
        private byte[] st_b = new byte[200];
        private long[] st_q = new long[25];
        
        private int pt = 0, rsiz = 0, mdlen = 0;
        
        private sha3_ctx_t() {
        	
        	super();
        }
        
        private void update_q( ) {
        	
        	for (int i=0; i < this.st_q.length; i++) {
        		this.st_q[i] = ((((long)st_b[i*8]) <<56) & 0xFF00000000000000L) | ((((long)st_b[i*8 + 1]) <<48) & 0x00FF000000000000L) |
        				((((long)st_b[i*8 + 2]) <<40) & 0x0000FF0000000000L) | ((((long)st_b[i*8 + 3]) <<32) & 0x000000FF00000000L) |
        				((((long)st_b[i*8 + 4]) <<24) & 0x00000000FF000000L) | ((((long)st_b[i*8 + 5]) <<16) & 0x0000000000FF0000L) |
        				((((long)st_b[i*8 + 6]) <<8) & 0x000000000000FF00L) | ((((long)st_b[i*8 + 7])) & 0x00000000000000FFL);
        	}
        	
        }
        
        private void update_b() {
        	int i, j;
        	for (byte b: this.st_b) {
        		System.out.printf("%x ", b);
        	}
        	System.out.println();
        	
        	System.out.println();
        	for(i=0; i < st_q.length; i++) {
        		for (j=0; j<8; j++) {
        			st_b[j + (8*i)] = ((byte) (st_q[i] >>> (64 - ((1+j)*8)))); 
        		}
        	}
        	
        }
    }
}