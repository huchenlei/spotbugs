package ca.utoronto.ece496.detector;

import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector2;
import edu.umd.cs.findbugs.ba.XMethod;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.ClassDescriptor;
import edu.umd.cs.findbugs.classfile.analysis.AnnotationValue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Created by Charlie on 20. 01 2019
 */
public class RequestMappingDetector implements Detector2 {
    /**
     * Entry point method full qualified name to be used for searching method in soot
     */
    private static List<String> entryPoints = new ArrayList<>();

    /**
     * Note: every detector type must have an constructor accepting a bugReporter
     * in order for the instance to be created
     * <p>
     * Note: better solution is to get all dependency injection part managed by Spring DI
     *
     * @param bugReporter bugReporter instance used to report bugs to outer scope
     */
    public RequestMappingDetector(BugReporter bugReporter) {

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

            if (!annotationValues.isEmpty()) entryPoints.add(xMethod.getSignature());
        }
    }

    /**
     * Initiate soot-infoflow process to analyze the project looking for XSS bugs
     * TODO
     */
    @Override
    public void finishPass() {

    }
}
