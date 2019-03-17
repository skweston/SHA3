import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Scanner;

/*
 *  This is still kind of a mess as I have been scrambling.
 * 
 * 
 */
public class TestDriver {
	
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
		            /*"9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10"*/
		        	"",
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
			
			//System.out.println("sha3");
			new sha3();
			//(String in, int inlen, byte[] md, int mdlen)
			byte[] b = new byte[32];
			byte[] c = new byte[1];
			String input = "";
			byte[] o123 = new byte[0x04];
			byte[] K = new byte[32];
			for (int g = 0; g < o123.length; g++) {
				o123[g] = (byte) g;
			}
			
			for (int h = 0; h < K.length; h++) {
				K[h] = (byte) (0x40 + h);
			}
			
			byte[] fucker = sha3.KMACXOF256("".getBytes(), "abc".getBytes(), 64, "D");
			for (byte _b : fucker) {
				System.out.printf("%02x", _b);
			}
			System.out.println();
			System.out.println(fucker.length);
			
			signFile("".getBytes());
			
			
			
			
//				System.out.printf("%x ", b[z]);
//			}
//			System.out.println();
			
			//byte[] b should = sha
			//for (int p=0; p<b.len)
			
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
	
	/*
	 * s <- KMACXOF256(pw, "", 512, "K"); s <- 4s;
	 * k <- KMACXOF256(s, m, 512, "N"); k<- 4k;
	 * U <- k*G;
	 * h <- KMACXOF256(Ux, m, 512, "T"); z <- (k - hs) mod r
	 * sigma <- (h, z)
	 */
	private static void signFile(byte[] m) {
		sha3 hash = new sha3();
		ECDHIES ec = new ECDHIES();
		Scanner input = new Scanner(System.in);
		input.useDelimiter("\n");
		Scanner file_scanner = null;
		
		System.out.println("File Name:");
		String file_in = input.next();
		try {
			file_scanner = new Scanner(new File(file_in));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		/* r = 2^519 − 337554763258501705789107630418782636071904961214051226618635150085779108655765 */
		
		BigInteger r = new BigInteger("2");
		r = r.pow(519);
		r = r.subtract(new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765"));
		
		
		//Generate s value
		BigInteger s = new BigInteger(hash.KMACXOF256("abc123".getBytes(), "".getBytes(), 512/8, "K"));
		
		if (s.compareTo(BigInteger.ZERO) < 0) {
			s = s.multiply(new BigInteger("-1"));
		}
		s = s.multiply(new BigInteger("4"));
		
		//generate k value
		
		BigInteger k = new BigInteger(sha3.KMACXOF256(s.toByteArray(), m, 512/8, "N"));
		if (k.compareTo(BigInteger.ZERO) < 0) {
			k = k.multiply(new BigInteger("-1"));
		}
		k = k.multiply(new BigInteger("4"));
		
		BigInteger[] G = ec.generateG();
		BigInteger[] U = {G[0].multiply(k), G[1].multiply(k)}; 
		BigInteger h = new BigInteger(hash.KMACXOF256(U[0].toByteArray(), m, 512/8, "T"));
		if (h.compareTo(BigInteger.ZERO) < 0) {
			h = h.multiply(new BigInteger("-1"));
		}
		BigInteger z = (k.subtract(h.multiply(s))).mod(r);
		BigInteger[] sigma = {h,z};
		
		System.out.println("Enter file name to write: ");
	    String file_out = input.next();
	    
	    BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new FileWriter(file_out));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    try {
			writer.write(sigma[0] + "\n");
			writer.write(sigma[1] + "\n");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	         
	    try {
			writer.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	//Runner of test code
	public static void main(String[] args) {
		if(test_sha3() == 0) {
			System.out.println("Success!");
			
		}
		
		//Will need an interactive aspect
	}
}