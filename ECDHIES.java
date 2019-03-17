/*
 *Author Shannon Weston
 *Version 1.1
 *Date 3/18/2019 
 */
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.math.BigInteger;
import java.nio.file.Files;

public class ECDHIES {
	private static BigInteger publicKey; //V
	private static BigInteger privateKey;  //s
	private static BigInteger p = new BigInteger("2").pow(521).subtract(new BigInteger("1"));
	private static BigInteger d = new BigInteger("-376014");
	
	private static PointOnCurve G = new PointOnCurve(BigInteger.ZERO, BigInteger.ZERO);
	
	public ECDHIES() {
		
	}

	private static String bytesToString(byte[] b) {
		String s = new String();

		int j = 0;
		char[] cr = new char[b.length * 2];
		for(int z = 0; z < b.length; z++) {
			byte y = b[z];
			int i = (y >>> 4) & 0x0F;
			int k = y & 0x0F;

			char c = 'a';
			char d = 'a';
			
			
			if(i >= 0 && i <= 9) {
				c = (char) (((int) i) + '0');
			}
			
			if(i >= 10 && i <= 15) {
				c = (char) ('a' + (char) (((int) i) % 10));
			}
			
			if(k >= 0 && k <= 9) {
				d = (char) (((int) k) + '0');
			}
			
			if(k >= 10 && k <= 15) {
				d = (char) ('a' + (char) (((int) k) % 10));
			}
			
			cr[j++] = c;
			cr[j++] = d;
		}
		
		s = new String(cr);

		return s;
	}

	public static String createKeyPair(byte[] b, String fileName) {
		generateG();
		byte[] s = generateS(b);
		byte[] v = generateV(s);
		System.out.println(v.length);

		String publicK = bytesToString(v);
		System.out.println(publicK);
		
		//to print key with byte spacing
		int j = 0;
		char[] c = publicK.toCharArray();
		char[] p = new char[(c.length * 2) - 1];
		for(int i = 0; i < publicK.length(); i++) {
			if(i == 0) {
				p[j++] = c[i];
			} else {
				if(i % 2 == 0) {
					p[j++] = ' ';
					p[j++] = c[i];
				} else {
					p[j++] = c[i];
				}
			}
		}
		
		publicK = new String(p);
		System.out.println("publicK: " + publicK);
		
		File f = new File("./" + fileName + ".txt");
		try {
			FileOutputStream fo = new FileOutputStream(f);
			try {
				fo.write(publicK.getBytes());
			} catch (IOException e) {
				e.printStackTrace();
			}
			
			//encrypt private key and print to file as well
			//requires part 4 and the same password that generated the keys
			String n = bytesToString(s);
			//System.out.println("private: " + n);
			//pass s to encrypt data to encrypt password
			
			try {
				fo.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		} catch (FileNotFoundException e) {
			System.out.println("file not found");
		}
		
		System.out.println("Keys saved to " + fileName + ".txt");
		return fileName;
	}

	public static BigInteger[] generateG() {
		BigInteger x = new BigInteger("18");
		BigInteger vNum = BigInteger.ONE.subtract(x.pow(2)).mod(p);
		BigInteger vDom = BigInteger.ONE.subtract(d.multiply(x.pow(2))).modInverse(p);
		BigInteger v = vNum.multiply(vDom).mod(p);
		//y^2 = (1-x^2)/(1-dx^2)
		BigInteger y = sqrt(v, p, false);
		
		G = new PointOnCurve(x, y);
		System.out.println("x: " + G.myX + " y: " + G.myY);
		BigInteger[] g = {x, y};
		return g;
	}
	
	private static byte[] generateS(byte[] pass) {
		new sha3();
		byte[] m = new byte[0];

		byte[] s = sha3.KMACXOF256(pass, m, 512/8, "K");
		System.out.println(s.length);
		
		return s;
	}
	
	private static byte[] generateV(byte[] s) {
		PointOnCurve V = G;
		
		for(int i = 0; i < s.length; i++) {
			for(int j = 0; j < 8; j++) {
				V = addPoints(V, V);
				int b = (int) (s[i] >> j) & 0x01; //does this sign extend correctly?
				if(b == 1) {
					V = addPoints(V, G);				
				}
			}
		}

		publicKey = V.myX; //correct?
		byte[] b = V.myX.toByteArray();
		return b;
	}
	
	public static PointOnCurve addPoints(PointOnCurve a, PointOnCurve b) {
		BigInteger xNum = a.myX.multiply(b.myY).add(a.myY.multiply(b.myX)).mod(p);
		BigInteger xDom = d.multiply(a.myX).multiply(b.myX).multiply(a.myY).multiply(b.myY).add(BigInteger.ONE).mod(p);
		
		BigInteger yNum = a.myY.multiply(b.myY).subtract(a.myX.multiply(b.myX)).mod(p);
		BigInteger yDom = BigInteger.ONE.subtract(d.multiply(a.myX.multiply(b.myX.multiply(a.myY.multiply(b.myY))))).mod(p);
		
		BigInteger newX = xNum.multiply(xDom.modInverse(p));
		BigInteger newY = yNum.multiply(yDom.modInverse(p));
		
		return new PointOnCurve(newX, newY);
	}
	
	public static BigInteger sqrt(BigInteger x, BigInteger p, boolean lsb) {
		assert(p.testBit(0) && p.testBit(1));
		
		if(x.signum() == 0) {
			return BigInteger.ZERO;
		}
		
		BigInteger r = x.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
		
		if(r.testBit(0) != lsb) {
			r = p.subtract(r);
		}
		
		return (r.multiply(r).subtract(x).mod(p).signum() == 0) ? r : null;
	}
	
	public static class PointOnCurve {
		public BigInteger myX;
		public BigInteger myY;
		
		public PointOnCurve(BigInteger x, BigInteger y) {
			myX = x;
			myY = y;
		}
	}
}