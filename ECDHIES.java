//ecc2
import java.math.BigInteger;

public class ECDHIES {
	private static BigInteger publicKey; //V
	private static BigInteger privateKey;  //s
	private static BigInteger p = new BigInteger("2").pow(521).subtract(new BigInteger("1"));
	private static BigInteger d = new BigInteger("-376014");
	
	private static PointOnCurve G = new PointOnCurve(BigInteger.ZERO, BigInteger.ZERO);
	
	public ECDHIES() {
		//comment
	}

	public static void createKeyPair(String passphrase) {
		generateG();
		byte[] s = generateS(passphrase);
		generateV(s);
	}
	
	public static void generateG() {
		BigInteger x = new BigInteger("18");
		BigInteger vNum = BigInteger.ONE.subtract(x.pow(2)).mod(p);
		BigInteger vDom = BigInteger.ONE.subtract(d.multiply(x.pow(2))).modInverse(p);
		BigInteger v = vNum.multiply(vDom).mod(p);
		//y^2 = (1-x^2)/(1-dx^2)
		BigInteger y = sqrt(v, p, false);
		
		G = new PointOnCurve(x, y);
		System.out.println("x: " + G.myX + " y: " + G.myY);
	}
	
	private static byte[] generateS(String pass) {
		new sha3();
		byte[] b = sha3.KMACXOF256(pass.getBytes(), "".getBytes(), 512/8, "K");
		
		/*for(int z = 0; z < b.length; z++) {
			System.out.printf("%x ", b[z]);
		}
		System.out.println();
		*/
		return b;
	}
	
	private static void generateV(byte[] s) {
		PointOnCurve V = new PointOnCurve(new BigInteger("0"), new BigInteger("0"));
		//need s as byte array
		
		for(int i = 0; i < s.length; i++) {
			for(int j = 0; j < 8; j++) {
				V = addPoints(V, V);
				int b = (int) (s[i] >> j) & 0x01; //does this sign extend correctly?
				if(b == 1) {
					V = addPoints(V, G);				
				}
			}
		}
		
		publicKey = V.myX;
	}
	
	public static PointOnCurve addPoints(PointOnCurve a, PointOnCurve b) {
		BigInteger xNum = a.myX.multiply(b.myY).add(a.myY.multiply(b.myX)).mod(p);
		BigInteger xDnom = d.multiply(a.myX).multiply(b.myX).multiply(a.myY).multiply(b.myY).add(BigInteger.ONE).mod(p);
		
		BigInteger yNum = a.myY.multiply(b.myY).subtract(a.myX.multiply(b.myX)).mod(p);
		BigInteger yDnom = BigInteger.ONE.subtract(d.multiply(a.myX.multiply(b.myX.multiply(a.myY.multiply(b.myY))))).mod(p);
		
		BigInteger newX = xNum.multiply(xDnom.modInverse(p));
		BigInteger newY = yNum.multiply(yDnom.modInverse(p));
		
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
	
	private static class PointOnCurve {
		private BigInteger myX;
		private BigInteger myY;
		
		public PointOnCurve(BigInteger x, BigInteger y) {
			myX = x;
			myY = y;
		}
	}
}
