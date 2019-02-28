public class sha3 {
	/** Defined number of transform rounds. */
	private static final int KECCAKF_ROUNDS = 24;
	
	/**NIST defined constants. */
	private static int[] rotc = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2,  14, 27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};
	
	/**NIST defined constants. */
	private static int[] piln = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};
	
	/**NIST defined constants. Get processed into values[] as Long */
	private static String constants = 
	        "0x0000000000000001,0x0000000000008082,0x800000000000808a,"
	        + "0x8000000080008000,0x000000000000808b,0x0000000080000001,"
	        + "0x8000000080008081,0x8000000000008009,0x000000000000008a,"
	        + "0x0000000000000088,0x0000000080008009,0x000000008000000a,"
	        + "0x000000008000808b,0x800000000000008b,0x8000000000008089,"
	        + "0x8000000000008003,0x8000000000008002,0x8000000000000080,"
	        + "0x000000000000800a,0x800000008000000a,0x8000000080008081,"
	        + "0x8000000000008080,0x0000000080000001,0x8000000080008008";
	
	/** Becomes the working array of constants.*/
	//Do we want these to be bytes?
	private static Long values[] = new Long[KECCAKF_ROUNDS]; //this should be long not Long
	
	/**Hash output */
	private static long output[];
	
	/**Expected output length. ? */
	private static int len = 0;
	private static int rsiz = 0;
	private static int point = 0;
	
	//Returns message digest String
	//Data Types are up for discussion
	public static String sha3Start(int[] message, int messageLength, int outputLength) {
		System.out.println("start");
		output = new long[outputLength]; //good.
		processConstants(); //good.
		
		sha3init(messageLength);
		sha3Rounds();
		sha3Complete();
		
		//st is the input string as 8bit chunks (two 4 bit hex values per index)
		long st[] = new long[messageLength];
		
		//is correct for 8 bit bytes
		/*System.out.println("message at input");
		for(int i = 0; i < messageLength; i++) {
			//fill st with message
			System.out.println(message[i]);
		}*/
		
		for(int i = 0; i < messageLength; i++) {
			//fill st with message
			st[i] = (long) message[i];
		}
		
		//is identical to message as longs
		/*System.out.println("st after input");
		for(int i = 0; i < messageLength; i++) {
			//fill st with message
			System.out.println(st[i]);
		}*/
		
		//Should the the completed hash - as String for final
		String s = "";
		/*for(int i = 0; i < output.length; i++) {
			System.out.printf("output[i]: %x\n", output[i]);
			System.out.println("output[i]: " + (char) output[i]);
			//s.concat(output[i]);
		}*/
		return s;
		//return output;
	}
	
	public sha3() {
		//can we initialize rsiz here?
		super();
	}
	
	
	private static void sha3init(int l) {
		System.out.println("init");
		len = l;
		
		//To convert between 64 and 8 bit words, may not need this.
		rsiz = 200 - 2 * len;
	}
	
	private int sha3_update(sha3_ctx_t c, byte[] data, int len)
	{
	    int i;
	    int j;

	    j = c.pt;
	    for (i = 0; i < len; i++) {
	        c.st_b[j++] ^= data[i];
	        if (j >= c.rsiz) {
	        	//TODO we need to figure out what this is doing and make the proper updates
	            keccak(c.st_q);
	            j = 0;
	        }
	    }
	    c.pt = j;

	    return 1;
	}
	
	private void sha3_final(byte[] md, sha3_ctx_t c)
	{
	    int i;

	    
	    //TODO Need to ask Paulo what this does. 
	    c->st.b[c.pt] ^= 0x06;
	    c->st.b[c.rsiz - 1] ^= 0x80;
	    
	    //TODO Need to make sure the st_q is updated before we perform this. Means we'll have to make two
	    //update functions in the sha3_ctx_t that update the long[] based on the byte[] and vice versa.
	    keccak(c.st_q);

	    for (i = 0; i < c->mdlen; i++) {
	        md[i] = c->st.b[i];
	    }

	    return 1;
	}

	
	private static void sha3Rounds() {
		//System.out.println("rounds");
		
	}
	
	private static void sha3Complete() {
		System.out.println("complete");
		
		//output[point] ^= 0x06; //6 at end of content (may have 000 until end)
		//output[rsiz - 1] ^= 0x80; //128 at last value
		
		//output = keccakf(output);
	}
	
	//Turns Strings into values we can use
	private static void processConstants() {
		System.out.println("constants");
		String[] hex = constants.split(",");
		//remove "0x" from constants
		for(int i = 0; i < hex.length; i++) {
			hex[i] = hex[i].substring(2, hex[i].length());
		}
		
		//positively sign the constants
		String plus = "+";
		for(int i = 0; i < hex.length; i++) {
			hex[i] = plus.concat(hex[i]);
		}

		//convert hex string to long
		for(int i = 0; i < hex.length; i++) {
			values[i] = Long.parseUnsignedLong(hex[i], 16);
		}
	}
	
	public byte[] sha3(String in, int inlen, byte[] md, int mdlen)
	{
	    sha3_ctx_t sha3 = new sha3_ctx_t();
	    sha3.mdlen = mdlen;
	    //TODO Shannon we need to turn the in string into a byte array that will get copied 
	    //to into the sha3.st_b byte array.
	    // After that we can 
	    byte[] in_as_bytes = string_to_byte_array(in);
	    sha3_update(sha3, in_as_bytes, in_as_bytes.length);
	    sha3_final(md, sha3);

	    return md;
	}

	//Does this replace processConstants?
	private byte[] string_to_byte_array(String input) {
		
		byte[] output = new byte[input.length()];
		
		for (int i=0; i < input.length(); i++) {
			output[i] = (byte) input.charAt(i);
		}
		
		
		return output;
	}
	
	
	private static long ROTL(long x, int y) {
		return ((x << y) | (x >> (64 - y)));
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
				/*System.out.println("theta");
				System.out.println(Long.toBinaryString(st[i]));
				System.out.println(Long.toBinaryString(st[i + 5]));
				System.out.println(Long.toBinaryString(st[i + 10]));
				System.out.println(Long.toBinaryString(st[i + 15]));
				System.out.println(Long.toBinaryString(st[i + 20]));*/
				bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
				//System.out.println(Long.toBinaryString(bc[i]));
			}
			
			for(i = 0; i < 5; i++) {
				t = bc[(i + 4) % 5] ^ ROTL(bc[(i + 1) % 5], 1);
				for(j = 0; j < 25; j++) {
					st[j + i] ^= t;
					st[j + i] = st[j + i] ^ (t);
				}
			}
			
			//Rho Pi
			t = st[1];
			for(i = 0; i <  24; i++) {
				/*j = piln[i];
				bc[0] = st[j];
				st[j] = ROTL(t, rotc[i]);
				st[j] = ROTL(t, rotc[i]);*/
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
			st[0] ^= values[r];
		}
		
		return st;
	}
	
    private class sha3_ctx_t {
        
        private byte[] st_b = new byte[200];
        private long[] st_q = new long[25];
        
        private int pt = 0, rsiz = 0, mdlen = 0;
        
        private sha3_ctx_t() {
        	
        	super();
        }
        
        
        
    }
}