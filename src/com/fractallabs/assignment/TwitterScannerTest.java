package com.fractallabs.assignment;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Timer;
import java.util.stream.Collectors;

import org.junit.Test;

import com.fractallabs.assignment.TwitterScanner.RequestMethod;

import static com.fractallabs.assignment.TwitterScanner.*;
import static com.fractallabs.assignment.TwitterScannerUtil.*;


public class TwitterScannerTest {
	
	/* Test using the signature base string and signing key as used in Twitter documantation at:
	 * https://developer.twitter.com/en/docs/basics/authentication/guides/creating-a-signature
	 */
	//@Test
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
	
	
	
	//@Test
	public void testSortMap() {
		Map<String, String> map = new HashMap<>();
		map.put("Zn", "Zinc");
		map.put("Na", "Sodium");
		map.put("He", "Helium");
		map.put("Hg", "Mercury");
		map.put("At", "Astatine");
		
		LinkedHashMap<String, String> lhMap = sortMap(map);
		List<String> keys = lhMap.keySet().stream().collect(Collectors.toList());
		
        List<String> keyRqr = Arrays.asList("At", "He", "Hg", "Na", "Zn");
        assertEquals(keyRqr, keys);
	} 
	
	
	/* CF example at
	 * https://developer.twitter.com/en/docs/basics/authentication/guides/creating-a-signature
	 */
	//@Test
	public void testPercentEncode() {
		String encoded = null;
		Optional<String> encodedOpt = percentEncode("An encoded string!");
		if (encodedOpt.isPresent()) {
			encoded = encodedOpt.get();
		}
		assertEquals(encoded, "An%20encoded%20string%21");
		
		encodedOpt = percentEncode("Dogs, Cats & Mice");
		if (encodedOpt.isPresent()) {
			encoded = encodedOpt.get();
		}
		assertEquals(encoded, "Dogs%2C%20Cats%20%26%20Mice");
		
		encodedOpt = percentEncode("Hello Ladies + Gentlemen, a signed OAuth request!");
		if (encodedOpt.isPresent()) {
			encoded = encodedOpt.get();
		}
		assertEquals(encoded, "Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21");
		
		encodedOpt = percentEncode("☃");
		if (encodedOpt.isPresent()) {
			encoded = encodedOpt.get();
		}
		System.out.println("\n☃ encoded: " + encoded);
		assertEquals(encoded, "%E2%98%83");
	}
	
	
	/* CF example at
	 * https://developer.twitter.com/en/docs/basics/authentication/guides/creating-a-signature
	 */
	//@Test
	public void testProcessSignature() {
		Map<String, String> parameters = new HashMap<>();
		parameters.put("oauth_signature_method", "HMAC-SHA1");
		parameters.put("oauth_timestamp", "1318622958");
		parameters.put("status", "Hello Ladies + Gentlemen, a signed OAuth request!");
		parameters.put("include_entities", "true");
		parameters.put("oauth_version", "1.0");
		parameters.put("oauth_consumer_key", "xvz1evFS4wEEPTGEFPHBog");
		parameters.put("oauth_nonce", "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg");
		parameters.put("oauth_token", "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb");
		
		String params =  processParameters(parameters);
		System.out.println("\n### params: " + params);
		assertEquals(params, "include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21");
		
		String baseURL = "https://api.twitter.com/1.1/statuses/update.json"; 
		Optional<String> optSigBase = signatureBaseString(RequestMethod.POST, baseURL, params);
		String sigBase = null;
		if (optSigBase.isPresent()) 
			sigBase = optSigBase.get();
		System.out.println("\n@@@ sigBase: " + sigBase);
		assertEquals(sigBase, "POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521");
		
		Optional<String> optSigningKey = signingKey(
				"kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw", "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE");
		String sigKey = null;
		if (optSigningKey.isPresent()) 
			sigKey = optSigningKey.get();
		System.out.println("\n$$$ sigKey: " + sigKey);
		assertEquals(sigKey, "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE");
		
		
		Optional<String> optSignature = processSignature(
				parameters,
				RequestMethod.POST, 
				baseURL,
				"kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw", 
				"LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE");
		String signature = null;
		if (optSignature.isPresent()) 
			signature = optSignature.get();
		System.out.println("\n*** signature: " + signature);
		assertEquals(signature, "hCtSmYh+iHYCEqBWrE7C7hYmtUk=");
	}
	
	
	//@Test
	public void testSendGet() {
		sendGet(URIGenerator(), "the");
	}
	
	
	/*
	 @Test
	public void testTimerTaskExecutor() {
		Timer timer = new Timer();
		timer.schedule(new TimerTaskExecutor(), 0, 5000); // 5 milliseconds
	}
	*/
	
	
	//@Test
	public void testPercentageChange() {
		assertEquals(-30, percentageChange(100, 70));
		assertEquals(0, percentageChange(70, 70));
		assertEquals(-100, percentageChange(70, 0));
		assertEquals(100, percentageChange(100, 200));
		assertEquals(-1, percentageChange(0, 100));
		assertEquals(0, percentageChange(0, 0));
		
		assertEquals("-30", percentChangeString(100, 70));
		assertEquals("0", percentChangeString(70, 70));
		assertEquals("-100", percentChangeString(70, 0));
		assertEquals("100", percentChangeString(100, 200));
		assertEquals("Infinity", percentChangeString(0, 100));
		assertEquals("0", percentChangeString(0, 0));
	}
	
	@Test
	public void testKeywordCount() { 
		assertEquals(2, keywordCount("fb", "abcfbdeFBghif b"));
		assertEquals(2, keywordCount("fB", "abcfbdeFBghif b"));
		assertEquals(5, keywordCount("fB", "fb FBfb fBFb"));
		assertEquals(0, keywordCount("fB", "abcd efg hij k"));
	}
}

