package com.rest.test;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;

import org.apache.http.HttpEntity;
//HTTP Client Dependency
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;

import java.io.BufferedInputStream;
//U
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

//Bouncy
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import org.apache.commons.codec.binary.Hex;

@Path("/tsa")
public class TimestampProxy {
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String test() {
    	System.out.println("get");
    	String peticion = "MEMCAQEwMTANBglghkgBZQMEAgEFAAQgmDSHbc+wXLFnpcJJU+uljErImxrfV/KPL50JrxB+6PACCxobHB4fKissLS4v";
    	String url = "http://dse200.ncipher.com/TSS/HttpTspServer";
    	//return requestTSABase64(peticion,url);
    	return "sdqd";
    }
    
    @POST
    @Produces(MediaType.TEXT_PLAIN)
    //public String post(String body_hex, @Context HttpHeaders header, @Context HttpServletResponse response){
    public String post(byte[] body, @Context HttpHeaders header, @Context HttpServletResponse response){

    	System.out.println("Post");
    	response.setHeader("Access-Control-Allow-Origin", "*");
    	String resp = "";
    	String str_request = "";
    	byte[] b_request = null;
	
	try{
    		//Check if body contains a Base64String request
    		b_request = Base64.decode(body);
    		System.out.println("Body contains a Base64String");
    		str_request = new String(body);
    		//b_request = str_request.getBytes();
    		System.out.println("Base64 String: "+str_request);
    	}catch (DecoderException e){
    		//Binary Request, so get its Bytes
    		b_request = body;
    		System.out.println("Body contains a Binary Request");
    		str_request = Base64.toBase64String(b_request);
    		System.out.println("Base64 String from input: "+str_request);
    		//e.printStackTrace();
    	}
    	
    	
    	//String url = "http://dse200.ncipher.com/TSS/HttpTspServer";
    	String url = "http://time.certum.pl";
	//String url = "https://freetsa.org/tsr";
    	return requestTimestamp(b_request,url);
    	
    	
    }
    
   
    public String requestTimestamp(byte[] b_request,String TSAurl){
    	String resp = "";

    	try {
    		CloseableHttpClient http_client = HttpClients.custom().disableContentCompression().build();   		
    		HttpPost post_request = new HttpPost(TSAurl);
    		ByteArrayEntity entity = new ByteArrayEntity(b_request);
    		
    		post_request.setHeader("Content-Type","application/timestamp-query");
    		post_request.setHeader("Accept", "application/timestamp-reply");
    		post_request.setHeader("Content-Transfer-Encoding", "base64");
    		post_request.setHeader("Accept-Encoding", "identity");
    		
    		post_request.setEntity(entity);
   		
    		CloseableHttpResponse response = null;
    		response = http_client.execute(post_request);

    		if (response.getStatusLine().getStatusCode() == 200){
        		HttpEntity responseEntity = response.getEntity();
        		//Read data as if always binary response
	    	        int contentLength = (int)responseEntity.getContentLength();
	    	        InputStream raw = response.getEntity().getContent();
	    	        InputStream in = new BufferedInputStream(raw);
	    	        byte[] data = new byte[contentLength];
	    	        int bytesRead = 0;
	    	        int offset = 0;

	    	        while (offset < contentLength) {
	    	          bytesRead = in.read(data, offset, data.length - offset);
	    	          if (bytesRead == -1)
	    	            break;
	    	          offset += bytesRead;
	    	        }
	    	        in.close();

	    	        if (offset != contentLength) {
	    	        	//throw new IOException("Only read " + offset + " bytes; Expected " + contentLength + " bytes");
	    	        	System.out.println("Only read " + offset + " bytes; Expected " + contentLength + " bytes");
	    	        }
	    	        //If the reading was OK, check whether the response is binary or a string
	    	        try{
		    		//Check if response contains a Base64 String 
		    		byte[] aux = Base64.decode(data);
		    		System.out.println("Response contains a Base64String TimestampResponse");
		    		//resp = Base64.toBase64String(aux);
		    		resp = new String(data);
		    		System.out.println("Base64 String: "+resp);
		    		
		    	}catch (DecoderException e){
		    		//Binary Request, so get the String
		    		resp = Base64.toBase64String(data);
		    		System.out.println("Response contains a Binary TimestampResponse");
		    		System.out.println("Base64 String from response: "+resp);
		    		//e.printStackTrace();
		    	}
	    	    	//resp = result.toString();
	    	    	//Close Response and Client
	    	    	response.close();
	    	    	http_client.close();
		}
    		
    	} catch (UnsupportedEncodingException e) {
    	    e.printStackTrace();
    	} catch (ClientProtocolException e) {
    	    e.printStackTrace();
    	} catch (IOException e) {
    	    //e.printStackTrace();
    	}
    	return resp;
    }
    
}
