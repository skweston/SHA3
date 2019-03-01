/*
 *  This is still kind of a mess as I have been scrambling.
 * 
 * 
 */
public class Driver {
	
	//Convert hex value as character to integer digit
	//Straight from .c
	private static int convertHexDigit(char c) {
		int digit = -1;
		
		if(c >= '0' && c <= '9') {
			digit = c - '0';
		}
		
		if(c >= 'A' && c <= 'F') {
			digit = c - 'A' + 10;
		}
		
		if(c >= 'a' && c <= 'f') {
			digit = c - 'a' + 10;
		}
			
		return digit;
	}
	
	//convert char[] to decimal int[] - creates 8 bit words
	//Straight from .c
	private static int testAndReadHex(int[] out, char c[], int max) {
		int h = 0, l = 0;
		int i;
		
		for(i = 0; i < (max/2); i++) {
			//System.out.println("i: " + i);
			h = convertHexDigit(c[2 * i]);
			if(h < 0) {
				return i;
			}
			l = convertHexDigit(c[2 * i + 1]);
			if(l < 0) {
				return i;
			}
			out[i] = (h << 4) + l;
		}
		g
		return i;
	}

	//Implementation of sha3 on set input
	public static int test_sha3() {
		// SHA3-224, corner case with 0-length message
		// SHA3-256, short message
		// SHA3-384, exact block size
		// SHA3-512, multi-block message
		//Test strings pulled from C implementation
		String[][] testMsg = {
		        {   
		            "9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10",
		            "2F1A5F7159E34EA19CDDC70EBF9B81F1A66DB40615D7EAD3CC1F1B954D82A3AF"
		        }
		};
		
		int fails = 0;
		int msg_len = 0, sha_len = 0;
		
		//Expected output
		//int[] sha = new int[64];
		
		
		int i;
		
		for(i = 0; i < testMsg.length; i++) {
			int[] msg;
			msg = new int[testMsg[i][0].toCharArray().length];
			msg_len = testAndReadHex(msg, testMsg[i][0].toCharArray(), msg.length);
			//sha_len = testAndReadHex(sha, testMsg[i][1].toCharArray(), sha.length);
			String sha = testMsg[i][1];
			sha_len = sha.length();
			
			/*System.out.println("message");
			for(int z = 0; z < msg_len; z++) {
				System.out.printf("%x ", msg[z]);
			}
			System.out.println();*/
			
			System.out.println("sha3");
			new sha3();
			//(String in, int inlen, byte[] md, int mdlen)
			byte[] b = new byte[32];
			sha3.sha3(testMsg[i][0], testMsg[i].length, b, sha.length());
			
			for(int z = 0; z < b.length; z++) {
				System.out.printf("%d ", b[z]);
			}
			System.out.println();
			
			//byte[] b should = sha
			String test = new String(b);
			System.out.println("test: " + test);
			
			
			//if not 0, then broken
			//fails = verifyOutput(sha, buf, sha_len, i);
			//fails = veriftyOutput(sha, md); //Possibility
		}
		
		return fails;
	}
	
	//checks the expected output against the program output
	private static int verifyOutput(int[] expected, int[] output, int length, int test) {
		System.out.println("verify");
		int fails = 0;
		for(int i = 0; i < length; i++) {
			//System.out.println("e:" + expected[i]);
			//System.out.println("o: " + output[i]);
			if(expected[i] != output[i]) {
				fails++;
				System.out.printf("Failure in %d", test);
			}
		}
		
		return fails;
	}
	
	//Runner of test code
	public static void main(String[] args) {
		if(test_sha3() == 0) {
			System.out.println("Success!");
		}
		
		//Will need an interactive aspect
	}
}