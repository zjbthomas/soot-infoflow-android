package soot.jimple.infoflow.android.TestApps;

import java.io.IOException;
import java.util.Set;

import org.xmlpull.v1.XmlPullParserException;

import soot.Scene;
import soot.SootMethod;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
import soot.jimple.infoflow.results.ResultSourceInfo;
import soot.options.Options;

public class ResultsHandler {
	public static void handleResults(InfoflowResults results) {
		/*
		for (ResultSinkInfo sink : results.getResults().keySet()) {
			for (ResultSourceInfo source : results.getResults().get(sink)) {
				if (source.getPath() != null) {
					for (Stmt path: source.getPath()) {
						System.out.println(path.toString());
					}
				}
				System.out.println(sink.toString() + "\n");
			}
		}
		*/
	}
}
