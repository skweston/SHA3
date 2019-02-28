public class sha3 {
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
	
	private int sha3_update(sha3_ctx_t c, byte[] data, int len)
	{
	    int i;
	    int j;

	    j = c.pt;
	    for (i = 0; i < len; i++) {
	        c.st_b[j++] ^= data[i];
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
	//this is for pushing
	private void sha3_final(byte[] md, sha3_ctx_t c)
	{
	    int i;

	    c.st_b[c.pt] ^= 0x06;
	    c.st_b[c.rsiz - 1] ^= 0x80;
	    
	    c.update_q();
	    keccak(c.st_q);
	    c.update_b();

	    for (i = 0; i < c.mdlen; i++) {
	        md[i] = c.st_b[i];
	    }
	}

		
	public byte[] sha3(String in, int inlen, byte[] md, int mdlen)
	{
	    sha3_ctx_t sha3 = new sha3_ctx_t();
	    sha3.mdlen = mdlen;
	    sha3.rsiz = 200 - (2*mdlen);
	    byte[] in_as_bytes = string_to_byte_array(in);
	    sha3_update(sha3, in_as_bytes, in_as_bytes.length);
	    sha3_final(md, sha3);

	    return md;
	}

	
	private byte[] string_to_byte_array(String input) {
		
		byte[] output = new byte[input.length()];
		
		for (int i=0; i < input.length(); i++) {
			output[i] = (byte) input.charAt(i);
		}
		
		
		return output;
	}
	
	
	private static long ROTL(long x, int y) {
		return ((x << y) | (x >>> (64 - y)));
	}
	
	private static long[] keccak(long st[]) {
		long t = 0;
		int j = 0, i = 0;
		long bc[] = new long[5];
		
		System.out.println("byte:");
		byte v = 0;
		for(i = 0; i < 25; i++) {
			System.out.println(Long.toBinaryString(st[i]));
			v = 0;
		}
		
		//Actual iteration
		for(int r = 0; r < KECCAKF_ROUNDS; r++) {
			
			//Theta
			for(i = 0; i < 5; i++) {
				bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
			}
			
			for(i = 0; i < 5; i++) {
				t = bc[(i + 4) % 5] ^ ROTL(bc[(i + 1) % 5], 1);
				for(j = 0; j < 25; j++) {
					st[j + i] ^= t;
				}
			}
			
			//Rho Pi
			t = st[1];
			for(i = 0; i <  KECCAKF_ROUNDS; i++) {
				j = piln[i];
				bc[0] = st[j];
				st[j] = ROTL(t, rotc[i]);
				st[j] = ROTL(t, rotc[i]);
			}
			
			//Chi
			for(j = 0; j < 25; j++) {
				
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
		
		return st;
	}
	
    private class sha3_ctx_t {
        
        private byte[] st_b = new byte[200];
        private long[] st_q = new long[25];
        
        private int pt = 0, rsiz = 136, mdlen = 0;
        
        private sha3_ctx_t() {
        	
        	super();
        }
        
        private void update_q( ) {
        	int j = 0;
        	for (int i=0; i < this.st_b.length; i++) {
        		
        		long temp = 0;
        		temp += st_b[i];
        		temp = temp << 8;
        		st_q[j] = temp;
        		if ((i+1) % 8 == 0) {
        			temp = 0;
        			j++;
        		}
        	}
        }
        
        private void update_b() {
        	int i, j;
        	
        	for(i=0; i < st_q.length; i++) {
        		for (j=0; j<8; j++) {
        			st_b[j + (8*i)] = ((byte) (st_q[i] >>> (64 - ((1+j)*8)))); 
        		}
        	}
        }
    }
}