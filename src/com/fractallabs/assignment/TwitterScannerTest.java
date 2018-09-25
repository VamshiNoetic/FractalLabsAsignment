package com.fractallabs.assignment;

import static org.junit.Assert.*;

import java.util.Base64;
import java.util.Formatter;
import java.util.Optional;
import org.junit.Test;
import static com.fractallabs.assignment.TwitterScanner.*;


public class TwitterScannerTest {
	
	/* Test using the signature base string and signing key as used in Twitter documantation at:
	 * https://developer.twitter.com/en/docs/basics/authentication/guides/creating-a-signature
	 */
	@Test
	public void testGenerateHMACSHA1() {
		byte[] hmac = null;
		Optional<byte[]> hmacOpt = generateHMACSHA1(
				"POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521",
				"kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE");
		if (hmacOpt.isPresent()) {
			hmac = hmacOpt.get();
		}
		System.out.println("\n" + toHexString(hmac));
		assertEquals(toHexString(hmac), "842b5299887e88760212a056ac4ec2ee1626b549");
		
		String base64 = base64(hmac, true);
		System.out.println("\n" + base64);
		assertEquals(base64, "hCtSmYh+iHYCEqBWrE7C7hYmtUk=");
	}
	
	
	private String toHexString(byte[] bytes) {
		Formatter formatter = new Formatter();
		for (byte b : bytes) {
			formatter.format("%02x", b);
		}
		String hex = formatter.toString();
		formatter.close();
		return hex;
	}
	
}
