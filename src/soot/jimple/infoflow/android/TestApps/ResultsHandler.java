package soot.jimple.infoflow.android.TestApps;

import java.util.ArrayList;
import java.util.HashMap;

import soot.jimple.Stmt;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
import soot.jimple.infoflow.results.ResultSourceInfo;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;

public class ResultsHandler {
	// Last for every single taint analysis
	public static IInfoflowCFG cfg = null;
	public static InfoflowResults results = null;
	
	// Last for all taint analysis
	public static IInfoflowCFG firstCfg = null;
	
	public static HashMap<Integer, String> passwordIds = null;
	public static ArrayList<Stmt[]> fromSourcesToEncryptions = null;
	
	public static ArrayList<String> output = null;
	
	public static void feedPasswordIds(HashMap<Integer, String> passPasswordIds) {
		passwordIds = passPasswordIds;
	}
	
	public static void feedResults(IInfoflowCFG passCfg, InfoflowResults passResults) {
		if (firstCfg == null) {
			firstCfg = passCfg;
		} else {
			cfg = passCfg;
		}
		results = passResults;
	}
	
	public static int handleResults() {	
		switch (SourcesSinksGenerator.getStage()) {
		case FromSourcesToEncryptions:
			for (ResultSinkInfo sink : results.getResults().keySet()) {
				for (ResultSourceInfo source : results.getResults().get(sink)) {
					if (source.getPath() != null) {
						// The current source should from source list
						boolean foundSource = false;
						for (String s : SourcesSinksGenerator.getSources()) {
							if (source.toString().contains(SourcesSinksGenerator.getMethodName(s))) {
								foundSource = true;
							}
						}
						if (!foundSource) {
							continue;
						}
						
						// The current source should contains one password ID
						boolean foundId = false;
						for (int id : passwordIds.keySet()) {
							if (source.toString().contains(String.valueOf(id))) {
								foundId = true;
								break;
							}
						}
						if (!foundId) {
							continue;
						}
						
						// Add current path to fromSourcesToEncryptions
						fromSourcesToEncryptions = new ArrayList<Stmt[]>();
						fromSourcesToEncryptions.add(source.getPath());
					}
				}
			}
			// Reset results
			cfg = null;
			results = null;
			
			return fromSourcesToEncryptions.size();
		case FromEncryptionsToSinks:
			for (ResultSinkInfo sink : results.getResults().keySet()) {
				for (ResultSourceInfo source : results.getResults().get(sink)) {
					if (source.getPath() != null) {
						// The current source should from encryption list
						boolean foundSource = false;
						for (String s : SourcesSinksGenerator.getSources()) {
							if (source.toString().contains(SourcesSinksGenerator.getMethodName(s))) {
								foundSource = true;
							}
						}
						if (!foundSource) {
							continue;
						}
						
						// Do mapping of encryption methods
						for (Stmt[] stmts : fromSourcesToEncryptions) {
							// Check if current source equals sink of last taint analysis
							if (source.toString().contains(stmts[stmts.length - 1].toString())) {
								// Detect ID
								int detectedId = 0;
								for (int id : passwordIds.keySet()) {
									if (stmts[0].toString().contains(String.valueOf(id))) {
										detectedId = id;
										break;
									}
								}
								// Output
								output = new ArrayList<String>();
								output.add("[IMPORTANT] Encryption " + SourcesSinksGenerator.getMethodName(source.toString()) + " found for " + passwordIds.get(detectedId));
								output.add("[IMPORTANT] Source: " + stmts[0].toString() + " in " + firstCfg.getMethodOf(stmts[0]).getSignature());
								output.add("[IMPORTANT] Sink: " + sink.toString());
								output.add("[IMPORTANT] Path:");
								for (int i = 0; i < stmts.length; i++) {
									output.add("[IMPORTANT] " + stmts[i].toString());
								}
								// Start from 1 in order to avoid duplicated encryption method
								for (int i = 1; i < source.getPath().length; i++) {
									output.add("[IMPORTANT] " + source.getPath()[i].toString());
								}
								output.add("---");
							}
						}
					}
				}
			}
			// Reset results
			cfg = null;
			results = null;
			
			return 0;
		case FromSourcesToSinks:
			for (ResultSinkInfo sink : results.getResults().keySet()) {
				for (ResultSourceInfo source : results.getResults().get(sink)) {
					if (source.getPath() != null) {
						// The current source should from source list
						boolean foundSource = false;
						for (String s : SourcesSinksGenerator.getSources()) {
							if (source.toString().contains(SourcesSinksGenerator.getMethodName(s))) {
								foundSource = true;
							}
						}
						if (!foundSource) {
							continue;
						}
						
						// The current source should contains one password ID
						int detectedId = 0;
						boolean foundId = false;
						for (int id : passwordIds.keySet()) {
							if (source.toString().contains(String.valueOf(id))) {
								detectedId = id;
								foundId = true;
								break;
							}
						}
						if (!foundId) {
							continue;
						}
						
						// Check path if it does not contain any encryption
						boolean foundEncryption = false;
						for (Stmt path: source.getPath()) {
							for (String s : SourcesSinksGenerator.getEncryptions()) {
								if (path.toString().contains(SourcesSinksGenerator.getMethodName(s))) {
									foundEncryption = true;
									break;
								}
							}
							if (foundEncryption) {
								break;
							}
						}
						if (foundEncryption) {
							continue;
						}
						
						// Add current path to fromSourcesToEncryptions
						output.add("[IMPORTANT] No encryption found for" + passwordIds.get(detectedId));
						output.add("[IMPORTANT] Source: " + source.toString() + " in " + cfg.getMethodOf(source.getSource()).getSignature());
						output.add("[IMPORTANT] Sink: " + sink.toString());
						for (int i = 0; i < source.getPath().length; i++) {
							output.add("[IMPORTANT] " + source.getPath()[i].toString());
						}
						output.add("---");
					}
				}
			}
			// Output
			for (String s : output) {
				System.out.println(s);
			}
			
			// Reset all parameters
			cfg = null;
			results = null;
			firstCfg = null;
			passwordIds = null;
			fromSourcesToEncryptions = null;
			output = null;
			
			return 0;
		}
		
		return 0;
	}
}
