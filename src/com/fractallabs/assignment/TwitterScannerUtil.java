package com.fractallabs.assignment;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Formatter;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import net.minidev.json.parser.ParseException;

import static com.fractallabs.assignment.TwitterScanner.*;


public class TwitterScannerUtil {
	

	static String readTimestamp(long ts) {
		Date date = new Date(ts * 1000L); 
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
		format.setTimeZone(TimeZone.getTimeZone("GMT-4"));
		return format.format(date);
	}
	
	static LinkedHashMap<String, String> sortMap(Map<String, String> map) {
		LinkedHashMap<Object, Object> result = map.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .collect(Collectors.toMap(
                		Map.Entry::getKey, 
                		Map.Entry::getValue,
                		(oldValue, newValue) -> oldValue, LinkedHashMap::new)
                		);
		LinkedHashMap<String,String> newMap= new LinkedHashMap<>();
		for(Object key: result.keySet())
		    newMap.put((String) key, (String) result.get(key));
		return newMap;
	}
	
	
	
	static Map<String, String> encodeMap(Map<String, String> target) {
		Map<String, String> result = new HashMap<>();
		for (Map.Entry<String,String> entry : target.entrySet()) {
			String key = entry.getKey();
			String value = entry.getValue();
			Optional<String> keyOpt = percentEncode(key);
			Optional<String> valueOpt = percentEncode(value);
			result.put(
					keyOpt.isPresent() ? keyOpt.get() : key,
					valueOpt.isPresent() ? valueOpt.get() : value
					);
		}
		return result;
	}
	
	
	
	static Optional<String> percentEncode(String target) {
		String result = null;
		try {
			result = URLEncoder.encode(target, "UTF-8").replace("+", "%20");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return Optional.empty();
		}
		return  Optional.ofNullable(result);
	}
	
	
	
	static String percentEncodeString(String target) {
		Optional<String> encodedOpt = percentEncode(target);
		return encodedOpt.isPresent() ? encodedOpt.get() : target;
	}
	
	
	
	static Optional<String> signatureBaseString(
			RequestMethod requestMethod, String baseURL, String parameters) {
		StringBuffer sb = new StringBuffer();
		String s;
		sb.append(requestMethod);
		
		sb.append("&");
		Optional<String> optBaseURL = percentEncode(baseURL);
		if (optBaseURL.isPresent()) 
			s = optBaseURL.get();
		else
			return Optional.empty();
		sb.append(s);
		
		sb.append("&");
		
		Optional<String> optParameters = percentEncode(parameters);
		if (optParameters.isPresent()) 
			s = optParameters.get();
		else
			return Optional.empty();
		sb.append(s);
		
		return Optional.ofNullable(sb.toString());
	}
	
	
	
	static Optional<String> signingKey(String consumerSectret, String accessTokenSectret) {
		StringBuffer sb = new StringBuffer();
		String s;
		
		Optional<String> optConsumerSectret = percentEncode(consumerSectret);
		if (optConsumerSectret.isPresent())
			s = optConsumerSectret.get();
		else
			return Optional.empty();
		sb.append(s);
		
		sb.append("&");
		
		Optional<String> optAccessTokenSectret = percentEncode(accessTokenSectret);
		if (optAccessTokenSectret.isPresent()) 
			s = optAccessTokenSectret.get();
		else
			return Optional.empty();
		sb.append(s);
		
		return Optional.ofNullable(sb.toString());
	}
	
	
	
	static String processParameters(Map<String, String> parameters) {
		Map<String, String> encodedMap = encodeMap(parameters);
		LinkedHashMap<String, String> lhMap = sortMap(encodedMap);
		
		StringBuffer sb = new StringBuffer();
		String prefix = "";
		for (Map.Entry<String,String> entry : lhMap.entrySet()) {
			String key = entry.getKey();
			String value = entry.getValue();
			sb.append(prefix);
			prefix = "&";
			sb.append(key);
			sb.append("=");
			sb.append(value);
		}
		return sb.toString();
	}
	
	
	
	static Optional<String> processSignature(
									Map<String, String> parameters,
									RequestMethod requestMethod, 
									String baseURL,
									String consumerSectret,
									String accessTokenSectret
									) {
		String sigBase = null;
		String sigKey = null;
		byte[] bytes = null;
		
		String params =  processParameters(parameters);
		
		Optional<String> optSigBase = signatureBaseString(requestMethod, baseURL, params);
		if (optSigBase.isPresent()) 
			sigBase = optSigBase.get();
		else
			return Optional.empty(); 
		 
		Optional<String> optSigningKey = signingKey(consumerSectret, accessTokenSectret);
		if (optSigningKey.isPresent()) 
			sigKey = optSigningKey.get();
		else
			return Optional.empty(); 
		
		Optional<byte[]> hmacOpt = generateHMACSHA1(sigBase, sigKey);
		if (hmacOpt.isPresent())
			bytes = hmacOpt.get();
		else
			return Optional.empty(); 
		
		String base64 = base64(bytes, true);
		return Optional.ofNullable(base64);
	}
	
	
	
	static String URIGenerator() {
		StringBuffer sb = new StringBuffer();
		sb.append(baseURL);
		sb.append("?");
		Map<String, String> params = getParameters();
		
		String prefix = "";
		for (Map.Entry<String, String> e : params.entrySet()) {
			sb.append(prefix);
			prefix = "&";
			sb.append(e.getKey());
			sb.append("=");
			sb.append(percentEncodeString(e.getValue()));
		}
		System.out.println("\n\n***   URIGenerator:\n" + sb);
		return sb.toString();
	}
	
	
	
	static String toHexString(byte[] bytes) {
		Formatter formatter = new Formatter();
		for (byte b : bytes) {
			formatter.format("%02x", b);
		}
		String hex = formatter.toString();
		formatter.close();
		return hex;
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
	
	
	
	static String generateRandomBase64() {
		double d = (Math.random() * 10000000000000d);
		byte[] bytes = new byte[8];
	    ByteBuffer buffer = ByteBuffer.allocate(bytes.length);
	    buffer.putDouble(d);
		String result = base64(buffer.array(), false);
		
		return result.length() == 11 ? result.substring(2,10) : result;
	}
	
	
	
	static String generateOAuthNonce() {
		return generateRandomBase64() + generateRandomBase64();
	}
	
	
	
	static String getTimestamp() {
		return "" + System.currentTimeMillis() / 1000;
	}
	
	
	
	static String base64(byte[] bytes, boolean withPadding) {
		return withPadding ?
				Base64.getEncoder().encodeToString(bytes)
				:
				Base64.getEncoder().withoutPadding().encodeToString(bytes);
	}
	
	
	
	static void sendGet(String url, String keyword)
	{
	   HttpURLConnection con = null;
	   String inputLine;
	   Integer responseCode = null;
	   try
	   {
	      URL obj = new URL(url);
	      con = (HttpURLConnection) obj.openConnection();
	      con.setRequestMethod("GET");
	      
	      con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
	      con.setRequestProperty("Accept-Charset", "UTF-8");
	      con.setRequestProperty("Content-Type", "text/plain; charset=utf-8");
	      
	      responseCode = con.getResponseCode();
	   }
	   catch (Exception e)
	   {
		   System.out.println("\n\nException for HttpURLConnection in sendGet() for URL " + url);
		   e.printStackTrace();
	   } 
	   if (responseCode == 200)
	   {
	      try
	      (
	         BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
	      )
	      {
	    	  while ((inputLine = in.readLine()) != null)
	    		  newVal.addAndGet(keywordCount(keyword, parseJSONTextField(inputLine)));
	      }
	      catch (Exception e)
	      {
	    	  e.printStackTrace();
	    	  System.out.println("\n\nException for InputStream in sendGet() for URL " + url + ". Returning null\n");
	      }
	   }
	}
	
	
	
	static boolean appendToFile(String fileName, String line) {
		try {
			FileWriter fw = new FileWriter(fileName, true);
			BufferedWriter bw = new BufferedWriter(fw);
		    bw.write(line);
		    bw.newLine();
		    bw.close();
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
	    return true;
	}
	
	
	
	static String parseJSONTextField(String inputLine) {
		JSONObject json = null;
		try {
			json = (JSONObject) JSONValue.parseWithException(inputLine);
		} catch (ParseException e) {
			e.printStackTrace();
			return "";
		}
		return (String) json.get("text");
	}
	
	
	
	static int keywordCount(String keyword, String target) {
		if (target == null)
			return 0;
		keyword = keyword.toLowerCase();
		target = target.toLowerCase();
		return (target.length() - target.replace(keyword, "").length()) / keyword.length();
	}
	
	
	static Properties loadOAuthProperties() {
		String path = System.getProperty("user.dir") + File.separator + "twitter.properties";
		System.out.println("path: " + path);
		
		Properties props = new Properties();
		try {
			props.load(new FileInputStream(path));
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		System.out.println("props: " + props);
		return props;
	}
	
	
	
	static int percentageChange(int prevVal, int newVal) {
		double d =  ((((double) newVal - (double) prevVal)) * 100 / (double) prevVal);
		System.out.println("D:  " + d);
		return (int) Math.round(d);
	}
	
	
	
	static String percentChangeString(int prevVal, int newVal) {
		Integer i = percentageChange(prevVal, newVal);
		return (i == -1 && prevVal == 0) ? "Infinity" : i.toString();
	}
	
	
	
	static int percentageChange(AtomicInteger prevVal, AtomicInteger newVal) {
		double d =  ((((double) newVal.intValue() - (double) prevVal.intValue())) 
				* 100 / (double) prevVal.intValue());
		System.out.println("D:  " + d);
		return (int) Math.round(d);
	}
	
	
	static double percentageChangeDouble(AtomicInteger prevVal, AtomicInteger newVal) {
		return ((((double) newVal.intValue() - (double) prevVal.intValue())) 
				* 100 / (double) prevVal.intValue());
	}
	
	
	static String percentChangeString(AtomicInteger prevVal, AtomicInteger newVal) {
		Integer i = percentageChange(prevVal, newVal);
		return (i == -1 && prevVal.intValue() == 0) ? "Infinity" : i.toString();
	}

}
