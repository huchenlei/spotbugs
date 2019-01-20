package ca.utoronto.ece496.detector;

import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector2;
import edu.umd.cs.findbugs.ba.XClass;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.ClassDescriptor;
import edu.umd.cs.findbugs.classfile.analysis.AnnotationValue;

/**
 * Created by Charlie on 20. 01 2019
 */
public class RequestMappingDetector implements Detector2 {
    /**
     * Note: every detector type must have an constructor accepting a bugReporter
     * in order for the instance to be created
     *
     * Note: better solution is to get all dependency injection part managed by Spring DI
     *
     * @param bugReporter bugReporter instance used to report bugs to outer scope
     */
    public RequestMappingDetector(BugReporter bugReporter) {

    }

    @Override
    public void visitClass(ClassDescriptor classDescriptor) throws CheckedAnalysisException {
        XClass xClass = classDescriptor.getXClass();

        System.out.println("Requst mapping detector!");
        for (AnnotationValue annotation : xClass.getAnnotations()) {
            System.out.println(annotation.getAnnotationClass().getDottedClassName());
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
