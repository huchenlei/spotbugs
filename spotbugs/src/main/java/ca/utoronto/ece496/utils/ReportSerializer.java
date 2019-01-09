package ca.utoronto.ece496.utils;

import com.google.gson.Gson;
import soot.jimple.infoflow.results.DataFlowResult;

/**
 * Serialization Util;
 * Responsible for serialization of flowdroid output in both JSON and XML format
 *
 * Created by Charlie on 09. 01 2019
 */
public class ReportSerializer {
    private static Gson gson = new Gson();

    /**
     * Warning, use the default conversion scheme in Gson
     * will result in stack overflow
     *
     * @param result
     * @return
     */
    public static String resultToJson(DataFlowResult result) {
        return gson.toJson(result);
    }
}
