package com.fractallabs.assignment;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;


public class TwitterScanner {
	
	enum RequestMethod{ POST, GET}
	
	
	public static class TSValue {
		
		private Instant timestamp;
		private double val;
		
		public TSValue(Instant timestamp, double val) {
			this.timestamp = timestamp;
			this.val = val;
		}
		
		public Instant getTimestamp() {
			return timestamp;
		}
		
		public double getVal() {
			return val;
		}
	}
	
	
	
	public TwitterScanner(String companyName){
		//...
	}
	
	
	
	public void run() {
		//..Begin aggregating mentions. Every hour, "store" the relative change
		//  (e.g. write it to System.out)
		System.out.println("TEST TwitterScanner...");
	}
	
	
	
	private void storeValue(TSValue value) {
		//...
	}
	
	
	static void processSignature(Map<String, String> parameters) {
		
	}
	
	
	static Optional<byte[]> generateHMACSHA1(String target, String key) {
		Mac mac = null;
		byte[] bytes = null;
		try {
			SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");
			mac = Mac.getInstance("HmacSHA1");
			mac.init(signingKey);
			bytes = mac.doFinal(target.getBytes());
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return Optional.empty();
		}
		return Optional.ofNullable(bytes);
	}
	
	
	
	static String base64(byte[] bytes, boolean withPadding) {
		return withPadding ?
				Base64.getEncoder().encodeToString(bytes)
				:
				Base64.getEncoder().withoutPadding().encodeToString(bytes);
	}
	
	
	
	public static void main(String... args) {
		TwitterScanner scanner = new TwitterScanner("Facebook");
		scanner.run();
	}
	
}
