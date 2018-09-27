package com.fractallabs.assignment;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.HashMap;
import java.util.LinkedHashMap;


import static com.fractallabs.assignment.TwitterScannerUtil.*;


public class TwitterScanner {
	
	private static Properties properties;
	
	static {
		properties = loadOAuthProperties();
		
		File file = new File("twitter_stats.dat");;
		try {
			Files.deleteIfExists(file.toPath());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private static final String oauthConsumerKey = properties.getProperty("consumerKey");
	private static final String oauthToken = properties.getProperty("accessToken");
	private static final String consumerSectret = properties.getProperty("consumerSecret");
	private static final String accessTokenSectret = properties.getProperty("accessTokenSecret");
	private static final String oauthSignatureMethod = "HMAC-SHA1";
	private static final String oauthVersion = "1.0";
	
	static final String baseURL = "https://stream.twitter.com/1.1/statuses/sample.json";
	
	static AtomicInteger prevVal = new AtomicInteger();
	static AtomicInteger newVal = new AtomicInteger();
	
	private String companyName;
	private static int flag = -1;

	static enum RequestMethod{POST, GET}
	
	
	
	public TwitterScanner(String companyName){
		this.companyName = companyName;
	}
	
	
	
	static Map<String, String> getParameters() {
		Map<String, String> parameters = new HashMap<>();
		//deterministic parameters
		parameters.put("oauth_consumer_key", oauthConsumerKey);
		parameters.put("oauth_token", oauthToken);
		parameters.put("oauth_signature_method", oauthSignatureMethod);
		parameters.put("oauth_version", oauthVersion);
		//generated parameters
		parameters.put("oauth_nonce", generateOAuthNonce());
		parameters.put("oauth_timestamp", getTimestamp());
		//generate oauth_signature
		Optional<String> optSignature = processSignature(
				parameters,
				RequestMethod.GET, 
				baseURL,
				consumerSectret, 
				accessTokenSectret);
		String signature = null;
		if (optSignature.isPresent()) 
			signature = optSignature.get();
		
		parameters.put("oauth_signature", signature);
		LinkedHashMap<String, String> lhMap = sortMap(parameters);
		return lhMap;
	}
	
	
	
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
	
	
	
	private void storeValue(TSValue value) {
		String line = value.getTimestamp().atZone(ZoneId.systemDefault()).toString()
						+ ":\t\t\t" + String.valueOf(value.getVal());
		
		appendToFile("twitter_stats.dat", line);
	}
	
	
	
	class TimerTaskExecutor extends TimerTask {
        public void run() {
        	//System.out.println("prevVal: " + prevVal + ",  newVal:  " + newVal);

        	TSValue tsValue = new TSValue(Instant.now(), percentageChangeDouble(prevVal, newVal));
            prevVal.set(newVal.intValue());
            newVal.set(0);
            
            if (flag > 0)
            	storeValue(tsValue);
            else
            	flag++;
        }
    }
	
	
	
	public void run() {
		Timer timer = new Timer();
		timer.schedule(new TimerTaskExecutor(), 0, 3600000); // rapid test with 5000
		sendGet(URIGenerator(), companyName);
	}
	
	
	
	public static void main(String... args) {
		TwitterScanner scanner = new TwitterScanner("Facebook"); // rapid test with "the"
		scanner.run();
	}
}

