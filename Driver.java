public class Driver {
	
	//Convert hex value as character to integer digit
	private static int convertHexDigit(char c) {
		int digit = -1;
		
		if(c >= '0' && c <= '9') {
			digit = c - '0';
		}
		
		if(c >= 'A' && c <= 'F') {
			digit = c - 'A' + 10; //why +10?
		}
		
		if(c >= 'a' && c <= 'f') {
			digit = c - 'a' + 10;
		}
			
		return digit;
	}
	
	//convert char[] to decimal int[] - creates 8 bit words
	private static int testAndReadHex(int[] out, char c[], int max) {
		int h = 0, l = 0;
		int i;
		
		for(i = 0; i < (max/2); i++) {
			System.out.println("i: " + i);
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
		        /*{   
		            "", // need to deal with this case.
		            "6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7"
		        },*/
		        {   
		            "9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10",
		            "2F1A5F7159E34EA19CDDC70EBF9B81F1A66DB40615D7EAD3CC1F1B954D82A3AF"
		        }/*,
		        {   
		            "E35780EB9799AD4C77535D4DDB683CF33EF367715327CF4C4A58ED9CBDCDD486" +
		            "F669F80189D549A9364FA82A51A52654EC721BB3AAB95DCEB4A86A6AFA93826D" +
		            "B923517E928F33E3FBA850D45660EF83B9876ACCAFA2A9987A254B137C6E140A" +
		            "21691E1069413848",
		            "D1C0FA85C8D183BEFF99AD9D752B263E286B477F79F0710B0103170173978133" +
		            "44B99DAF3BB7B1BC5E8D722BAC85943A"
		        },
		        {   
		            "3A3A819C48EFDE2AD914FBF00E18AB6BC4F14513AB27D0C178A188B61431E7F5" +
		            "623CB66B23346775D386B50E982C493ADBBFC54B9A3CD383382336A1A0B2150A" +
		            "15358F336D03AE18F666C7573D55C4FD181C29E6CCFDE63EA35F0ADF5885CFC0" +
		            "A3D84A2B2E4DD24496DB789E663170CEF74798AA1BBCD4574EA0BBA40489D764" +
		            "B2F83AADC66B148B4A0CD95246C127D5871C4F11418690A5DDF01246A0C80A43" +
		            "C70088B6183639DCFDA4125BD113A8F49EE23ED306FAAC576C3FB0C1E256671D" +
		            "817FC2534A52F5B439F72E424DE376F4C565CCA82307DD9EF76DA5B7C4EB7E08" +
		            "5172E328807C02D011FFBF33785378D79DC266F6A5BE6BB0E4A92ECEEBAEB1",
		            "6E8B8BD195BDD560689AF2348BDC74AB7CD05ED8B9A57711E9BE71E9726FDA45" +
		            "91FEE12205EDACAF82FFBBAF16DFF9E702A708862080166C2FF6BA379BC7FFC2"
		        }*/
		};
		
		int fails = 0;
		int msg_len = 0, sha_len = 0;
		
		int[] sha = new int[64];
		int[] buf = new int[64];		
		
		int i;
		
		 
		for(i = 0; i < 1; i++) {
			int[] msg;
			msg = new int[testMsg[i][0].toCharArray().length];
			msg_len = testAndReadHex(msg, testMsg[i][0].toCharArray(), msg.length);
			sha_len = testAndReadHex(sha, testMsg[i][1].toCharArray(), sha.length);
			
			System.out.println("message");
			for(int z = 0; z < msg_len; z++) {
				System.out.printf("%x ", msg[z]);
			}
			System.out.println();
			
			System.out.println("sha3");
			new sha3();
			String c = sha3.sha3Start(msg, msg_len, sha_len);
			
			for(int z = 0; z < c.length(); z++) {
				//System.out.println(c[z]);
			}
			
			/*for(int z = 0; z < sha.length; z++) {
				System.out.println("sha: " + sha[z]);
			}
			for(int z = 0; z < buf.length; z++) {
				System.out.println("buf: " + buf[z]);
			}
			System.out.println("sha_len: " + sha_len);
			System.out.println("i: " + i);*/
			
			//if not 0, then broken
			//fails = verifyOutput(sha, buf, sha_len, i);
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