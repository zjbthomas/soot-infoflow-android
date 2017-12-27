package soot.jimple.infoflow.android.TestApps;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SourcesSinksGenerator {
	public enum Stage {
		FromSourcesToConversions,
		FromConversionsToSinks,
		FromSourcesToSinks
	};
	
	public static Stage currentStage;
	
	public final static String[] directSources = {
			"<android.support.design.widget.TextInputEditText: android.text.Editable getText()>",
			"<android.widget.EditText: android.text.Editable getText()>",
			"<android.widget.TextView: java.lang.CharSequence getText()>",
			"<android.app.Activity: android.view.View findViewById(int)>",
			"<android.support.v4.app.FragmentActivity: android.view.View findViewById(int)>",
			"<android.support.v7.app.AppCompatActivity: android.view.View findViewById(int)>"
	};
	
	public final static String[] indirectSources = {
			"<android.app.Activity: android.view.View findViewById(int)>",
			"<android.support.v4.app.FragmentActivity: android.view.View findViewById(int)>",
			"<android.support.v7.app.AppCompatActivity: android.view.View findViewById(int)>",
			"<android.support.design.widget.TextInputEditText: android.text.Editable getText()>",
			"<android.widget.EditText: android.text.Editable getText()>",
			"<android.widget.TextView: java.lang.CharSequence getText()>"
	};
	
	public final static String[] conversions = {
			"<java.security.MessageDigest: byte[] digest()>",
			"<java.security.MessageDigest: byte[] digest(byte[])>",
			"<java.security.MessageDigest: int digest(byte[], int, int)>",
			"<javax.crypto.Cipher: int doFinal(byte[], int, int, byte[])>",
			"<javax.crypto.Cipher: int doFinal(byte[], int)>",
			"<javax.crypto.Cipher: byte[] doFinal()>",
			"<javax.crypto.Cipher: byte[] doFinal(byte[])>",
			"<javax.crypto.Cipher: int doFinal(byte[], int, int, byte[], int)>",
			"<javax.crypto.Cipher: int doFinal(java.nio.ByteBuffer, java.nio.ByteBuffer)>",
			"<javax.crypto.Cipher: byte[] doFinal(byte[], int, int)>"
	};
	
	public final static String[] sinks = {
			"<java.net.HttpURLConnection: void connect()>",
			"<com.android.volley.RequestQueue: com.android.volley.Request add(com.android.volley.Request)>",
			"<java.io.OutputStream: void flush()>",
			"<java.io.BufferedOutputStream: void flush()>",
			"<java.io.OutputStreamWriter: void flush()>",
			"<com.squareup.okhttp.Call: com.squareup.okhttp.Response execute()>",
			"<retrofit2.Call: void enqueue(retrofit2.Callback)>",
			"<java.net.URL: java.net.URLConnection openConnection()>",
			"<java.net.URLConnection: void connect()>",
			"<org.apache.http.client: org.apache.http.HttpResponse execute(org.apache.http.HttpHost, org.apache.http.HttpRequest)>",
			"<org.apache.http.client: org.apache.http.HttpResponse execute(org.apache.http.HttpHost, org.apache.http.protocol.HttpContext)>",
			"<org.apache.http.client: java.lang.Object execute(org.apache.http.HttpHost, org.apache.http.HttpRequest, org.apache.http.client.ResponseHandler)>",
			"<org.apache.http.client: java.lang.Object execute(org.apache.http.HttpHost, org.apache.http.HttpRequest, org.apache.http.client.ResponseHandler, org.apache.http.protocol.HttpContext)>",
			"<org.apache.http.client: org.apache.http.HttpResponse execute(org.apache.http.HttpRequest)>",
			"<org.apache.http.client: org.apache.http.HttpResponse execute(org.apache.http.HttpRequest, org.apache.http.protocol.HttpContext)>",
			"<org.apache.http.client: java.lang.Object execute(org.apache.http.HttpRequest, org.apache.http.client.ResponseHandler)>",
			"<org.apache.http.client: java.lang.Object execute(org.apache.http.HttpRequest, org.apache.http.client.ResponseHandler, org.apache.http.protocol.HttpContext)>",
			"<java.net.Socket: java.io.OutputStream getOutputStream()>"
	};
	
	private final static String sourceAndSinks = "../soot-infoflow-android/SourcesAndSinks.txt";
	
	public static String getMethodName(String method) {
		Pattern p = Pattern.compile("[a-zA-Z_$][a-zA-Z0-9]+\\(");
		Matcher m = p.matcher(method);
		m.find();
		return method.substring(m.start(), m.end() - 1);
	}
	
	public static void fromSourcesToEncryption(boolean direct) throws FileNotFoundException {
		PrintWriter writer = new PrintWriter(sourceAndSinks);
		for (String s : (direct? directSources: indirectSources)) {
			writer.println(s + " -> _SOURCE_");
		}for (String s : conversions) {
			writer.println(s + " -> _SINK_");
		}
        writer.close();
        
        currentStage = Stage.FromSourcesToConversions;
	}
	
	public static void fromEncryptionToSinks() throws FileNotFoundException {
		PrintWriter writer = new PrintWriter(sourceAndSinks);
		for (String s : conversions) {
			writer.println(s + " -> _SOURCE_");
		}for (String s : sinks) {
			writer.println(s + " -> _SINK_");
		}
        writer.close();
        
        currentStage = Stage.FromConversionsToSinks;
	}
	
	public static void fromSourcesToSinks(boolean direct) throws FileNotFoundException {
		PrintWriter writer = new PrintWriter(sourceAndSinks);
		for (String s : (direct? directSources: indirectSources)) {
			writer.println(s + " -> _SOURCE_");
		}for (String s : sinks) {
			writer.println(s + " -> _SINK_");
		}
        writer.close();
        
        currentStage = Stage.FromSourcesToSinks;
	}
	
	public static String[] getSources(boolean direct) {
		switch (currentStage) {
		case FromSourcesToConversions:
			return (direct? directSources: indirectSources);
		case FromConversionsToSinks:
			return conversions;
		case FromSourcesToSinks:
			return (direct? directSources: indirectSources);
		}
		return null;
	}
	
	public static String[] getEncryptions() {
		return conversions;
	}
	
	public static String[] getSinks() {
		switch (currentStage) {
		case FromSourcesToConversions:
			return conversions;
		case FromConversionsToSinks:
			return sinks;
		case FromSourcesToSinks:
			return sinks;
		}
		return null;
	}
	
	public static Stage getStage() {
		return currentStage;
	}
}
