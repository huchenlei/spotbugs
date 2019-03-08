package ca.utoronto.ece496.utils;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import soot.jimple.infoflow.Infoflow;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.results.DataFlowResult;
import soot.jimple.infoflow.results.InfoflowResults;

import java.util.Arrays;
import java.util.Set;

/**
 * Created by Charlie on 09. 01 2019
 * The test instance shall no longer be used
 */
@Deprecated
@Ignore
public class ReportSerializerTest {
    public static InfoflowResults analysis() {
        Infoflow infoflow = new Infoflow();

        InfoflowConfiguration config = infoflow.getConfig();
        config.setImplicitFlowMode(InfoflowConfiguration.ImplicitFlowMode.NoImplicitFlows);

        infoflow.computeInfoflow(
                "src/test/resources/ecs.jar",
                "",
                "<app_kvECS.ECSClient: void main(java.lang.String[])>",
                Arrays.asList(
                        "<java.io.BufferedReader: java.lang.String readLine()>"
                ),
                Arrays.asList(
                        "<ecs.ECS: ecs.IECSNode addNode(java.lang.String,int)>",
                        "<ecs.ECS: boolean removeNodes(java.util.Collection)>",
                        "<app_kvECS.ECSClient: void handleCommand(java.lang.String)>",
                        "<app_kvECS.ECSClient: void printError(java.lang.String)>"
                )
        );

        return infoflow.getResults();
    }

    private static Set<DataFlowResult> resultSet;

    @BeforeClass
    public static void beforeAll() {
        InfoflowResults results = analysis();
        resultSet = results.getResultSet();
        results.printResults();
    }

    @Test
    public void testToJson() {
        for (DataFlowResult dataFlowResult : resultSet) {
            // Do something useful possibly?
            // TODO remove following lines if necessary
            System.out.println(dataFlowResult);
        }
        System.out.println("It's working!");
    }
}
