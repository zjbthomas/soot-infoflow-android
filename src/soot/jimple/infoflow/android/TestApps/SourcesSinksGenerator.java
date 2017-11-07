package soot.jimple.infoflow.android.TestApps;

import java.io.FileNotFoundException;
import java.io.PrintWriter;

public class SourcesSinksGenerator {
	public enum Stage {
		FromSourcesToEncryptions,
		FromEncryptionsToSinks,
		FromSourcesToSinks
	};
	
	public static Stage currentStage;
	
	public final static String[] sources = {
			"<android.app.Activity: android.view.View findViewById(int)>",
			"<android.support.v7.app.AppCompatActivity: android.view.View findViewById(int)>"
	};
	public final static String[] encryptions = {
			"<java.security.MessageDigest: byte[] digest()>"
	};
	public final static String[] sinks = {
			"<java.net.HttpURLConnection: void connect()>",
			"<com.android.volley.RequestQueue: com.android.volley.Request add(com.android.volley.Request)>",
			"<java.io.OutputStream: void flush()>",
			"<com.squareup.okhttp.Call: com.squareup.okhttp.Response execute()>"
	};
	
	private final static String sourceAndSinks = "../soot-infoflow-android/SourcesAndSinks.txt";
	
	public static String getMethodName(String method) {
		String[] splitBySpace = method.split(" ");
		return splitBySpace[splitBySpace.length - 1].replaceAll("\\(.?\\)>", "");
	}
	
	public static void fromSourcesToEncryption() throws FileNotFoundException {
		PrintWriter writer = new PrintWriter(sourceAndSinks);
		for (String s : sources) {
			writer.println(s + " -> _SOURCE_");
		}for (String s : encryptions) {
			writer.println(s + " -> _SINK_");
		}
        writer.close();
        
        currentStage = Stage.FromSourcesToEncryptions;
	}
	
	public static void fromEncryptionToSinks() throws FileNotFoundException {
		PrintWriter writer = new PrintWriter(sourceAndSinks);
		for (String s : encryptions) {
			writer.println(s + " -> _SOURCE_");
		}for (String s : sinks) {
			writer.println(s + " -> _SINK_");
		}
        writer.close();
        
        currentStage = Stage.FromEncryptionsToSinks;
	}
	
	public static void fromSourcesToSinks() throws FileNotFoundException {
		PrintWriter writer = new PrintWriter(sourceAndSinks);
		for (String s : sources) {
			writer.println(s + " -> _SOURCE_");
		}for (String s : sinks) {
			writer.println(s + " -> _SINK_");
		}
        writer.close();
        
        currentStage = Stage.FromSourcesToSinks;
	}
	
	public static String[] getSources() {
		switch (currentStage) {
		case FromSourcesToEncryptions:
			return sources;
		case FromEncryptionsToSinks:
			return encryptions;
		case FromSourcesToSinks:
			return sources;
		}
		return null;
	}
	
	public static String[] getEncryptions() {
		return encryptions;
	}
	
	public static String[] getSinks() {
		switch (currentStage) {
		case FromSourcesToEncryptions:
			return encryptions;
		case FromEncryptionsToSinks:
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
