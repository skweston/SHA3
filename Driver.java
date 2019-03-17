/*
 *Authors Shannon Weston and James Haines-Temons
 *Date of release 3/18/2019
 *Version 1.1 
 */

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Scanner;
import static java.nio.file.StandardOpenOption.*;
import java.nio.file.*;
import java.io.*;

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
			byte[] b = sha3.cSHAKE256(input.getBytes(), L, N, S);
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
			byte[] b = sha3.KMACXOF256(key.getBytes(), input.getBytes(), L/8, S);
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
		//sha3.sha3(input, input.length(), b, b.length);
		//sha3.kmacxof256("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F", input, 512, "My Tagged Application");
		
		b = sha3.KMACXOF256(new byte[0], input.getBytes(), 512/8, "D");
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
		
		boolean direct = false;
		
		//Get integer random and convert to a byte array.
		SecureRandom random = new SecureRandom();
		int z = random.nextInt(512);
		int n = 1 , i = 0;
		while (1 << 8*n <= z) n++;
		byte[] z_as_byte = new byte[n--];
		do { 
			z_as_byte[n - i] = (byte) ((z >>> 8*i) & 0x0FFL);
			i++;
		} while (i <= n);
		
//		System.out.println("b");
//		for(int z = 0; z < b.length; z++) {
//			System.out.printf("%x", b[z]);
//		}
//		System.out.println();
		
		new sha3();
		
		Scanner dataScan = new Scanner(System.in);
		dataScan.useDelimiter("\n");
		System.out.println("Insert Passphrase for Encryption:");
		String pw = dataScan.next();
		System.out.println("Type message for Encryption:");
		String message = dataScan.next();
		byte[] m = message.getBytes();
		
		byte[] key = concat(z_as_byte, pw.getBytes());
		byte[] keka = sha3.KMACXOF256(key, "".getBytes(), 1024/8 /* for bytes not bits*/, "S");
		
		int ke_ka_size = keka.length / 2;
		byte [] ke = new byte[ke_ka_size];
		byte[] ka = new byte[ke_ka_size];
		for (int j = 0; j < ke.length; j++) {
			ke[j] = keka[j];
			ka[j] = keka[j + ke_ka_size];
		}
		
		/* c <- KMACXOF256(ke, "", |m|, "SKE") xor m */
		byte[] c = sha3.KMACXOF256(ke, "".getBytes(), m.length, "SKE");
		
		for(i = 0; i < c.length; i++) {
			c[i] ^= m[i];
		}
		
		byte[] t = sha3.KMACXOF256(ka, message.getBytes(), 512/8, "SKA");
		//write cryptogram to file
		
		String z_as_string = string_builder(z_as_byte);
		String c_as_string = string_builder(c);
		String t_as_string = string_builder(t);
		
	    String output = z_as_string + "\n" + c_as_string + "\n" + t_as_string;
		
	    System.out.println("Enter file name to write: ");
	    String file_out = dataScan.next();
	    
	    BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new FileWriter(file_out));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    try {
			writer.write(output);
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
	
	/* (z, c, t)
	 * (ke || ka) <- KMACXOF256(z || pw, "", 1024,  "S")
	 * m <- KMACXOF256(ke, "", |c|, "SKE") xor c
	 * t' <- KMACXOF256(ka, m, 512, "SKA")
	 * accept only iff t' = t
	 */
	/**
	 * Reads bytes from a file. File must be formated with z value on first line as space delimited bytes
	 * c must also be space delimited bytes on the second line
	 * t must also be space delimited bytes on the third line
	 */
	private static void symmetricDecrypt() {
		
		boolean correct = true;
		Scanner input = new Scanner(System.in);
		Scanner file_scanner = null;
		file_scanner.useDelimiter("\n");
		
		System.out.println("File Name:");
		String file_in = input.next();
		try {
			file_scanner = new Scanner(new File(file_in));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		byte[] z = get_bytes_from_string(file_scanner.next());
		byte[] c = get_bytes_from_string(file_scanner.next());
		byte[] t = get_bytes_from_string(file_scanner.next());
		
//		//Test input is same as text file
//		for (byte b : z) {
//			System.out.printf("%02x ", b);
//		}
//		System.out.println();
//		for (byte b : c) {
//			System.out.printf("%02x ", b);
//		}
//		System.out.println();
//		for (byte b : t) {
//			System.out.printf("%02x ", b);
//		}
//		System.out.println();
		
		System.out.println("Enter the password:");
		String pw = input.next();
		
		byte[] z_pw = concat(z, pw.getBytes());
		byte[] keka = sha3.KMACXOF256(z_pw, "".getBytes(), 1024/8, "S");
		
		
		int ke_ka_size = keka.length / 2;
		byte [] ke = new byte[ke_ka_size];
		byte[] ka = new byte[ke_ka_size];
		for (int i = 0; i < ke.length; i++) {
			ke[i] = keka[i];
			ka[i] = keka[i + ke_ka_size];
		}
		
		/* m <- KMACXOF256(ke, "", |c|, "SKE") xor c */
		byte[] m = sha3.KMACXOF256(ke, "".getBytes(), c.length, "SKE");
		for (int j = 0; j < m.length; j++) {
			m[j] ^= c[j];
		}
		
		
		byte[] t_prime = sha3.KMACXOF256(ka, m, 512/8, "SKA");
		for (int k = 0; k < t_prime.length; k++) {
			correct = (t[k] == t_prime[k]);
		}
		
		if (correct) {
			System.out.println("Password Accepted - Message output:");
			System.out.println(new String(m));
		} else {
			System.out.println("Password Failed.");
		}
		
		
		
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
	 * k <- KMACXOF256(s, m, 512, "N"); k<- 4k;
	 * U <- k*G;
	 * h <- KMACXOF256(Ux, m, 512, "T"); z <- (k - hs) mod r
	 * sigma <- (h, z)
	 */
	private static void signFile() {
		
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
		
		byte[] m = get_bytes_from_string(file_scanner.next());
		
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
	

	/*
	 * U <- x*G + h*V
	 * accept iff KMACXOF256(Ux, m, 512, "T") = h
	 */
	private static void verifySignature() {

	}
	
	/**
	 * concatenates two byte arrays
	 * @param a		The string desired to be in the front of the resulting array
	 * @param b		The string that will be at the back of the resulting array
	 * @return		"a" + "b"
	 */
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
	
	private static String string_builder(byte[] b) {
	    StringBuilder sb = new StringBuilder();
	    for (byte s : b) {
	        sb.append(String.format("%02X ", s));
	    }
	    
		return sb.substring(0, sb.substring(0).length() - 1);
		
	}
	/*     int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));
    }
    return data;
	}*/
	private static byte[] get_bytes_from_string(String s) {
		String[] s_split = s.split(" ");
		byte[] result = new byte[s_split.length];
		for (int i = 0; i < s_split.length; i++) {
			result[i] = (byte) ((Character.digit(s_split[i].charAt(0), 16) << 4) + Character.digit(s_split[i].charAt(1), 16));
			
		}
		return result;
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