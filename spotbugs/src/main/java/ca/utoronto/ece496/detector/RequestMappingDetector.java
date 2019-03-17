package ca.utoronto.ece496.detector;

import ca.utoronto.ece496.spring.SpringAppEntryPointCreator;
import ca.utoronto.ece496.utils.GeneralUtil;
import ca.utoronto.ece496.utils.SootFormatAdapter;
import edu.umd.cs.findbugs.*;
import edu.umd.cs.findbugs.ba.AnalysisContext;
import edu.umd.cs.findbugs.ba.XMethod;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.ClassDescriptor;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import edu.umd.cs.findbugs.classfile.analysis.AnnotationValue;
import soot.jimple.Stmt;
import soot.jimple.infoflow.Infoflow;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.results.DataFlowResult;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
import soot.jimple.infoflow.results.ResultSourceInfo;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Created by Charlie on 20. 01 2019
 */
@SuppressWarnings("PackageAccessibility")
public class RequestMappingDetector implements Detector2 {

    /**
     * Entry point method full qualified name to be used for searching method in soot
     */
    private static List<String> entryPoints = new ArrayList<>();

    private final BugReporter bugReporter;

    private final BugAccumulator accumulator;

    /**
     * Note: every detector type must have an constructor accepting a bugReporter
     * in order for the instance to be created
     * <p>
     * Note: better solution is to get all dependency injection part managed by Spring DI
     *
     * @param bugReporter bugReporter instance used to report bugs to outer scope
     */
    public RequestMappingDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
        this.accumulator = new BugAccumulator(bugReporter);
    }

    /**
     * Note: seems like we don't actually need to check @Controller for each class visited
     * because @RequestMapping annotation can be used everywhere, not necessarily within a
     * Controller
     *
     * @param classDescriptor descriptor naming the class to visit
     * @throws CheckedAnalysisException None
     */
    @Override
    public void visitClass(ClassDescriptor classDescriptor) throws CheckedAnalysisException {
        for (XMethod xMethod : classDescriptor.getXClass().getXMethods()) {
            List<AnnotationValue> annotationValues = xMethod.getAnnotations().stream().filter(annotationValue ->
                    Arrays.asList(
                            "org.springframework.web.bind.annotation.RequestMapping",
                            "org.springframework.web.bind.annotation.GetMapping",
                            "org.springframework.web.bind.annotation.PostMapping",
                            "org.springframework.web.bind.annotation.PutMapping",
                            "org.springframework.web.bind.annotation.DeleteMapping",
                            "org.springframework.web.bind.annotation.PatchMapping"
                    ).contains(annotationValue.getAnnotationClass().getDottedClassName()))
                    .collect(Collectors.toList());

            if (!annotationValues.isEmpty())
                entryPoints.add(SootFormatAdapter.toSootMethodString(xMethod.getMethodDescriptor()));
        }
    }

    /**
     * Initiate soot-infoflow process to analyze the project looking for XSS bugs
     * TODO accept user config from external file
     */

    @Override
    public void finishPass() {
        Project project = GeneralUtil.accessField(
                AnalysisContext.class, "project",
                AnalysisContext.currentAnalysisContext()
        );
        assert project != null;

        Infoflow infoflow = new Infoflow();

        // following items shall come from config file
        InfoflowConfiguration config = new InfoflowConfiguration();
        InfoflowConfiguration.PathConfiguration pathConfiguration = config.getPathConfiguration();
        pathConfiguration.setPathReconstructionMode(InfoflowConfiguration.PathReconstructionMode.Precise);

        // Note the content of source/sink should come from user config
        List<String> sources = new ArrayList<>(
                Arrays.asList("<java.io.BufferedReader: java.lang.String readLine()>")
        );

        List<String> sinks = new ArrayList<>(
                Arrays.asList("<java.io.PrintStream: void println(java.lang.String)>")
        );

        // -end-

        sources.add(SpringAppEntryPointCreator.getDefaultSourceSignature());
        sinks.add(SpringAppEntryPointCreator.getDefaultSinkSignature());

        infoflow.setConfig(config);
        infoflow.computeInfoflow(
                String.join(File.pathSeparator, project.getAuxClasspathEntryList().toArray(new String[]{})),
                String.join(File.pathSeparator, project.getFileArray()),
                new SpringAppEntryPointCreator(entryPoints),
                sources,
                sinks
        );

        reportBugs(infoflow.getResults());
    }

    private static String getSootSignatureFromStmt(Stmt stmt) {
        return stmt.containsInvokeExpr() ? stmt.getInvokeExpr().getMethod().toString() : "<unknown: void unknown()>";
    }

    private void reportBugs(InfoflowResults results) {
        for (DataFlowResult dataFlowResult : results.getResultSet()) {
            ResultSinkInfo sink = dataFlowResult.getSink();
            ResultSourceInfo source = dataFlowResult.getSource();

            Stmt[] path = source.getPath();
            LinkedList<Stmt> fullPath =
                    path != null ? new LinkedList<>(Arrays.asList(path)) : new LinkedList<>();

            fullPath.addFirst(source.getStmt());
            fullPath.addLast(sink.getStmt());

            String sinkMethod = getSootSignatureFromStmt(sink.getStmt());
            String sinkDescription =
                    sinkMethod.equals(SpringAppEntryPointCreator.getDefaultSinkSignature()) ?
                            "Default Sink (Return value of request handling method)" :
                            sinkMethod;

            String sourceMethod = getSootSignatureFromStmt(source.getStmt());
            String sourceDescription =
                    sourceMethod.equals(SpringAppEntryPointCreator.getDefaultSourceSignature()) ?
                            "Default Source (Input param of request handling method)" :
                            sinkMethod;

            List<MethodDescriptor> descriptors = fullPath.stream()
                    .filter(Stmt::containsInvokeExpr)
                    .map(stmt -> SootFormatAdapter.toMethodDescriptor(getSootSignatureFromStmt(stmt)))
                    .collect(Collectors.toList());

            assert !descriptors.isEmpty();

            MethodDescriptor mainDescriptor = descriptors.stream()
                    .filter(
                            d -> !Arrays.asList(
                                    SpringAppEntryPointCreator.getDefaultSinkSignature(),
                                    SpringAppEntryPointCreator.getDefaultSourceSignature()
                            ).contains(SootFormatAdapter.toSootMethodString(d))
                    ).collect(Collectors.toList()).get(0); // note: there must be at least one real(not dummy)  method call in the path

            List<SourceLineAnnotation> sourceLineAnnotations = descriptors.stream()
                    .map(SourceLineAnnotation::forFirstLineOfMethod
                    ).collect(Collectors.toList());

            bugReporter.reportBug(
                    new BugInstance(this, "GENERAL_XSS", Priorities.NORMAL_PRIORITY)
                            .addString(sourceDescription)
                            .addString(sinkDescription)
                            .addAnnotations(sourceLineAnnotations)
                            .addClassAndMethod(mainDescriptor)
            );
        }
    }
}
