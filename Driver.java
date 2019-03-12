import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Scanner;

public class Driver {
	//Driver
	
	//Test
	private static void test() {
		System.out.println("Which algorithm would you like to test?");
		System.out.println("\ta) Sha3");
		System.out.println("\tb) cShake");
		System.out.println("\tc) KMACXOF");
		Scanner dataScan = new Scanner(System.in);
		new sha3();
		
		String choice = "";
		if(dataScan.hasNext()) {
			choice = dataScan.next();
		}
		if(choice.equals("a")) {
			//sha3
			byte[] b = new byte[32];
			System.out.println("Choose known input string: ");
			System.out.println("\ta) abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
			System.out.println("\tb) abc");
			System.out.println("\tc) \"\"");
			choice = dataScan.next();
			String input = "";
			String output = "";
			if(choice.equals("a")) {
				input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
				output = "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376";
			} else if(choice.equals("b")) {
				input = "abc";
				output = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
			} else if(choice.equals("c")) {
				output = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
			}
			sha3.sha3(input, input.length(), b, b.length);
			for(int z = 0; z < b.length; z++) {
				System.out.printf("%x", b[z]);
			}
			System.out.println();
			System.out.println("expected output: " + output);
		} else if(choice.equals("b")) {
			//cShake
			//cSHAKE256(String X, int L, String N, String S)
			String input = "";
			int L = 0;
			String N = "";
			String S = "";
			byte[] b = sha3.cSHAKE256(input, L, N, S);
			for(int z = 0; z < b.length; z++) {
				System.out.printf("%x", b[z]);
			}
			System.out.println();
			//System.out.println("expected output: " + output);
		} else if(choice.equals("c")) {
			//kmacxof
			//KMACXOF256(String K, String X, int L, String S)
			//https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMACXOF_samples.pdf #5
			String key = "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F";
			String S = "";
			String input = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F" + 
					"303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F" + 
					"707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F" + 
					"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7";
			String output = "FF7B171F1E8A2B24683EED37830EE797538BA8DC563F6DA1E667391A75EDC02CA633079F81CE12A25F45615EC89972031D18337331D24CEB8F8CA8E6A19FD98B";
			int L = 512;
			byte[] b = sha3.KMACXOF256(key, input, L, S);
			for(int z = 0; z < b.length; z++) {
				System.out.printf("%x", b[z]);
			}
			System.out.println();
			System.out.println("expected output: " + output);
		}
		
		dataScan.close();
	}
	
	//Generate Key Pair
	private static void genKeyPair() { 
		new ECDHIES();
		String s = "";
		Scanner sc = new Scanner(System.in);
		System.out.println("Insert passphase for desired key: ");
		s = sc.next();
		ECDHIES.createKeyPair(s);
		ECDHIES.generateG();
		sc.close();
	}
	
	//Secure Data
	private static void secureData() { 
		System.out.println("What would you like to secure? "); 
		Scanner dataScan = new Scanner(System.in);
		System.out.println("\ta) Text input");
		System.out.println("\tb) File by name");
		String choice = "";
		if(dataScan.hasNext()) {
			choice = dataScan.next();
		}
		
		if(choice.equals("a")) {
			System.out.println("Choose an option: ");
			System.out.println("\ta) Hash Text Input");
			System.out.println("\tb) Encrypt Text Input");
			System.out.println("\tc) Decrypt Text Input");
			choice = dataScan.next();
			if(choice.equals("a")) {
				hashTextInput();
			} else if(choice.equals("b")) {
				ellipticEncryptText();
			} else if(choice == "c") {
				ellipticDecryptText();
			}
		}
		
		if(choice.equals("b")) {
			System.out.println("Choose an option: ");
			System.out.println("\ta) Hash File Input");
			System.out.println("\tb) Symmetrically Secure File");
			System.out.println("\tc) Elliptically Secure File");
			System.out.println("\td) Sign a File");
			choice = dataScan.next();
			if(choice.equals("a")) {
				hashFileInput();
			} else if(choice.equals("b")) {
				System.out.println("Encrypt or Decrypt File?");
				System.out.println("\ta) Encrypt");
				System.out.println("\tb) Decrypt");
				choice = dataScan.next();
				if(choice.equals("a")) {
					symmetricEncrypt();
				} else if(choice.equals("b")) {
					symmetricDecrypt();
				}
			} else if(choice.equals("c")) {
				System.out.println("Encrypt or Decrypt File?");
				System.out.println("\ta) Encrypt");
				System.out.println("\tb) Decrypt");
				choice = dataScan.next();
				if(choice.equals("a")) {
					ellipticEncryptFile();
				} else if(choice.equals("b")) {
					ellipticDecryptFile();
				}
			} else if(choice.equals("d")) {
				signFile();
			}
		}
		
		dataScan.close();
	}
	
	//Secure Data
	private static void hashFileInput() { 
		System.out.println("Input filename: ");
		Scanner s = new Scanner(System.in);
		String file = s.next();
		String input = "";
		try {
			input = new String(Files.readAllBytes(Paths.get(file)));
		} catch (IOException e) {
			System.out.println("File not found: hashFileInput()");
			e.printStackTrace();
		}
		new sha3();
		byte[] b = new byte[32];//?
		sha3.sha3(input, input.length(), b, b.length);
		//sha3.kmacxof256("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F", input, 512, "My Tagged Application");
		System.out.println(input);
		for(int z = 0; z < b.length; z++) {
			System.out.printf("%x ", b[z]);
		}
		System.out.println();
		s.close();
	}
	
	//Secure Data - not good yet
	private static void hashTextInput() { 
		System.out.println("Input text to be hashed in one line and press Enter: ");
		Scanner s = new Scanner(System.in);
		StringBuilder str = new StringBuilder();
		while(s.hasNext()) {
			String var = s.next();
			System.out.println(var);
			if(var.equals(" ")) {
				break;
			}
			str.append(var);
		}
		
		System.out.println(str.toString());
		s.close(); 
		//pass to sha3
		/*for(int z = 0; z < b.length; z++) {
			System.out.printf("%x ", b[z]);
		}
		System.out.println();*/
	}
	
	/*
	 * z<- Random(512)
	 * (ke || ka) <- KMACXOF(z || pw, "", 1024, "S)
	 * c <- KMACXOF256(ke, "", |m|, "SKE") xor m
	 * t <- KMACXOF256(ka, m, 512, "SKA")
	 * cryptogram: (z, c, t)
	 */ 
	private static void symmetricEncrypt() {
		SecureRandom random = new SecureRandom();
		byte[] b = new byte[512];
		random.nextBytes(b);
		
		System.out.println("b");
		for(int z = 0; z < b.length; z++) {
			System.out.printf("%x", b[z]);
		}
		System.out.println();
		
		new sha3();
		
		Scanner dataScan = new Scanner(System.in);
		System.out.println("Insert Passphrase for Encryption");
		String pass = dataScan.next();
		String rand = b.toString(); //this is still wrong
		String key = rand.concat(pass);
		byte[] keka = sha3.KMACXOF256(key, "", 1024, "S");
		System.out.println("keka");
		for(int z = 0; z < keka.length; z++) {
			System.out.printf("%x", keka[z]);
		}
		System.out.println();
		
		System.out.println("length: " + keka.length);
		byte[] ke = new byte[keka.length/2];
		byte[] ka = new byte[keka.length/2];
		
		for(int i = 0; i < keka.length/2; i++) {
			int j = 0;
			if(i < keka.length/2) {
				ke[j++] = keka[i];
			} else {
				ka[j++] = keka[i];
			}
		}
		
		String input = "";
		char[] ins = input.toCharArray();
		System.out.println("ke");
		for(int z = 0; z < ke.length; z++) {
			System.out.printf("%x", ke[z]);
		}
		System.out.println();
		System.out.println(ke.length);
		System.out.println(ka.length);
		System.out.println("ka");
		for(int z = 0; z < ka.length; z++) {
			System.out.printf("%x", ka[z]);
		}
		System.out.println();
		/*byte[] c = sha3.KMACXOF256(ke.toString(), "", input.length(), "SKE");
		
		for(int i = 0; i < c.length; i++) {
			c[i] ^= ins[i];
		}
		
		byte[] t = sha3.KMACXOF256(ka.toString(), input, 512, "SKA");*/
		//write cryptogram to file
		dataScan.close();
	}
	
	/* (z, c, t)
	 * (ke || ka) <- KMACXOF256(z || pw, "", 1024,  "S")
	 * m <- KMACXOF256(ke, "", |c|, "SKE") xor c
	 * t' <- KMACXOF256(ka, m, 512, "SKA")
	 * accept only iff t' = t
	 */
	private static void symmetricDecrypt() {
		//read in file
		String z = "";
		//z = random value
		//c = 
		//t = 
		String c = "";
		System.out.println("Insert filename to decrypt");
		Scanner dataScan = new Scanner(System.in);
		String file = dataScan.next();
		String input = "";
		try {
			input = new String(Files.readAllBytes(Paths.get(file)));
		} catch (IOException e) {
			System.out.println("File not found: hashFileInput()");
			e.printStackTrace();
		}
		new sha3();
		String pass = dataScan.next();
		String key = z.concat(pass);
		byte[] m = sha3.KMACXOF256(key, "", c.length(), "S");
		
	}
	
	/*
	 * k <- Random(512); k <- 4k;
	 * W <- k*V; Z<-k*G;
	 * (ke || ka) <- KMACXOF256(Wx, "", 1024, "P");
	 * c <- KMACXOF256(ke, "", |m|, "PKE") XOR m
	 * t <- KMACXOF256(ka, m, 512, "PKA")
	 * cryptogram: (Z, c, t)
	 */
	private static void ellipticEncryptFile() {
		System.out.println("Input filename: ");
		Scanner s = new Scanner(System.in);
		String file = s.next();
		String input = "";
		try {
			input = new String(Files.readAllBytes(Paths.get(file)));
		} catch (IOException e) {
			System.out.println("File not found: ellipticEncryptFile()");
			e.printStackTrace();
		}
		new sha3();
		byte[] b = new byte[32];//?
		sha3.sha3(input, input.length(), b, b.length);
		//sha3.kmacxof256("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F", input, 512, "My Tagged Application");
		System.out.println(input);
		for(int z = 0; z < b.length; z++) {
			System.out.printf("%x ", b[z]);
		}
		System.out.println();
		s.close();
	}
	
	/*
	 * s <- KMACXOF256(pw, "", 512, "K"); s <- 4s
	 * W <- s*Z
	 * (ke || ka) <- KMACXOF256(wx, "", 1024, "P")
	 * m <- KMACXOF256(ke, "", |c|, "PKE") xor c
	 * t' <- KMACXOF256(ka, m, 512, "PKA")
	 * if and only if t' = t
	 */
	private static void ellipticDecryptFile() {
		
	}
	
	/*
	 * k <- Random(512); k <- 4k;
	 * W <- k*V; Z<-k*G;
	 * (ke || ka) <- KMACXOF256(Wx, "", 1024, "P");
	 * c <- KMACXOF256(ke, "", |m|, "PKE") XOR m
	 * t <- KMACXOF256(ka, m, 512, "PKA")
	 * cryptogram: (Z, c, t)
	 */
	private static void ellipticEncryptText() {
		
	}
	
	/*
	 * s <- KMACXOF256(pw, "", 512, "K"); s <- 4s
	 * W <- s*Z
	 * (ke || ka) <- KMACXOF256(wx, "", 1024, "P")
	 * m <- KMACXOF256(ke, "", |c|, "PKE") xor c
	 * t' <- KMACXOF256(ka, m, 512, "PKA")
	 * if and only if t' = t
	 */
	private static void ellipticDecryptText() {
		
	}
	
	/*
	 * s <- KMACXOF256(pw, "", 512, "K"); s <- 4s;
	 * k <- KMACXOF256(x, m, 512, "N"); k<- 4k;
	 * U <- k*G;
	 * h <- KMACXOF256(Ux, m, 512, "T"); z <- (k - hs) mod r
	 * sigma <- (h, z)
	 */
	private static void signFile() {
		
	}

	/*
	 * U <- x*G + h*V
	 * accept iff KMACXOF256(Ux, m, 512, "T") = h
	 */
	private static void verifySignature() {

	}

	//Runner of test code
	public static void main(String[] args) {
		System.out.println("hello");
		System.out.println("Select an option:");
		
		//For Demo
		System.out.println("\ta) Test algorithms");
		
		//Part 1
		System.out.println("\tb) Generate Key Pair");
		
		//Part 1 Bonus
		System.out.println("\tc) Secure Data");
		
		Scanner s = new Scanner(System.in);
		String c = s.next();
		switch (c) {
			case "a":
				test();
				break;
			case "b": 
				genKeyPair();
				break;
			case "c": 
				secureData();
				break;
			default:
				break;
		}
		s.close();
	}
}