package ca.utoronto.ece496.utils;

import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import org.apache.bcel.classfile.Utility;
import soot.jimple.infoflow.data.SootMethodAndClass;
import soot.jimple.infoflow.util.SootMethodRepresentationParser;
import org.apache.bcel.generic.Type;


/**
 * Created by Charlie on 07. 03 2019
 * Deal with conversion between soot method format and other formats
 */
@SuppressWarnings("PackageAccessibility")
public class SootFormatAdapter {
    public static MethodDescriptor toMethodDescriptor(String sootMethodString) {
        SootMethodAndClass methodAndClass = SootMethodRepresentationParser.v().parseSootMethodString(sootMethodString);

        return new MethodDescriptor(
                methodAndClass.getClassName().replace('.', '/'), // class name
                methodAndClass.getMethodName(),
                Type.getMethodSignature(
                        Type.getType(Utility.getSignature(methodAndClass.getReturnType())),
                        methodAndClass.getParameters().stream()
                                .filter(param -> !param.equals(""))
                                .map(param -> Type.getType(Utility.getSignature(param)))
                                .toArray(Type[]::new)
                )
        );
    }
}