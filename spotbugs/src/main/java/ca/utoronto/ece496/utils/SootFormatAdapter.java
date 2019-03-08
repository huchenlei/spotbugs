package ca.utoronto.ece496.utils;

import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import org.apache.bcel.classfile.Utility;
import org.apache.bcel.generic.Type;
import soot.jimple.infoflow.data.SootMethodAndClass;
import soot.jimple.infoflow.util.SootMethodRepresentationParser;

import java.util.Arrays;


/**
 * Created by Charlie on 07. 03 2019
 * Deal with conversion between soot method format and other formats
 */
@SuppressWarnings("PackageAccessibility")
public class SootFormatAdapter {
    /**
     * Convert a sootMethodString to MethodDescriptor instance which is used by BCEL
     *
     * @param sootMethodString soot method string // a string enclosed by \<\>
     * @return MethodDescriptor instance
     */
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

    /**
     * Convert MethodDescriptor instance to an soot method signature string
     *
     * @param descriptor MethodDescriptor
     * @return soot method signature string which is enclosed by \<\>
     */
    public static String toSootMethodString(MethodDescriptor descriptor) {
        String signature = descriptor.getSignature();
        Type[] argumentTypes = Type.getArgumentTypes(signature);
        Type returnType = Type.getReturnType(signature);

        return "<" +
                descriptor.getClassDescriptor().getDottedClassName() + ": " +
                returnType + " " +
                descriptor.getName() +
                "(" + String.join(",", Arrays.stream(argumentTypes).map(Type::toString).toArray(String[]::new)) + ")" +
                ">";
    }
}