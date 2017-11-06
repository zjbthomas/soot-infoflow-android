package soot.jimple.infoflow.android.TestApps;

import java.io.IOException;
import java.util.HashMap;
import java.util.Set;

import org.xmlpull.v1.XmlPullParserException;

import soot.Scene;
import soot.SootMethod;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
import soot.jimple.infoflow.results.ResultSourceInfo;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;
import soot.options.Options;

public class ResultsHandler {
	public static HashMap<Integer, String> passwordIds = null;
	public static IInfoflowCFG cfg = null;
	public static InfoflowResults results = null;
	public final static String[] encryptionList = {
			"doFinal",
			"digest"
			};
	
	public static void feedPasswordIds(HashMap<Integer, String> passPasswordIds) {
		passwordIds = passPasswordIds;
	}
	
	public static void feedResults(IInfoflowCFG passCfg, InfoflowResults passResults) {
		cfg = passCfg;
		results = passResults;
	}
	
	public static void handleResults() {
		if (passwordIds == null || cfg == null || results == null) {
			System.out.println("[IMPORTANT] One of the arguments is null");
			return;
		}
		
		for (ResultSinkInfo sink : results.getResults().keySet()) {
			for (ResultSourceInfo source : results.getResults().get(sink)) {
				if (source.getPath() != null) {
					int detectedId = 0;
					String detectedEncryption = "";
					// The current source should contains one password ID
					boolean foundId = false;
					for (int id : passwordIds.keySet()) {
						if (source.toString().contains(String.valueOf(id))) {
							detectedId = id;
							foundId = true;
							break;
						}
					}
					if (!foundId) {
						//System.out.println("[IMPORTANT] No ID found in source " + source.toString() + ", skipped");
						continue;
					}
					// Check path if it contains any encryption
					boolean foundEncryption = false;
					for (Stmt path: source.getPath()) {
						for (String s : encryptionList) {
							if (path.toString().contains(s)) {
								detectedEncryption = s;
								foundEncryption = true;
								break;
							}
						}
						if (foundEncryption) {
							break;
						}
					}

					// Output results
					System.out.println("[IMPORTANT] " + (foundEncryption? ("Encryption " + detectedEncryption) : "No encryption") + " found for " + passwordIds.get(detectedId));
					System.out.println("[IMPORTANT] Source: " + source.toString() + " in " + cfg.getMethodOf(source.getSource()).getSignature());
					System.out.println("[IMPORTANT] Sink: " + sink.toString());
					System.out.println("---");
				}
			}
		}
		
		HashMap<Integer, String> passwordIds = null;
		IInfoflowCFG cfg = null;
		InfoflowResults results = null;
	}
}
