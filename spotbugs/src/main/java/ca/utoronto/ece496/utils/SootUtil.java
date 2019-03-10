package ca.utoronto.ece496.utils;

import soot.*;
import soot.dava.internal.javaRep.DIntConstant;
import soot.jimple.*;

import java.util.Collection;

/**
 * Created by Charlie on 09. 03 2019
 */
@SuppressWarnings("PackageAccessibility")
public class SootUtil {
    public static SootClass createClass(String className, Collection<SootMethod> methods) {
        if (Scene.v().containsClass(className))
            return Scene.v().getSootClass(className);

        SootClass sootClass = new SootClass(className, Modifier.PUBLIC);
        sootClass.setSuperclass(Scene.v().getSootClass("java.lang.Object"));

        for (SootMethod method : methods) {
            sootClass.addMethod(method);
        }

        Scene.v().addClass(sootClass);
        return sootClass;
    }

    public static SootMethod createEmptyMethod(SootMethod target) {
        JimpleBody body = Jimple.v().newBody(target);
        target.setActiveBody(body);

        int paramCount = 0;
        for (Type parameterType : target.getParameterTypes()) {
            Local arg = Jimple.v().newLocal("p" + paramCount, parameterType);
            body.getLocals().add(arg);

            body.getUnits().add(Jimple.v().newIdentityStmt(
                    arg, Jimple.v().newParameterRef(parameterType, paramCount)
            ));

            paramCount++;
        }

        Type returnType = target.getReturnType();

        Stmt returnStmt;
        if (target.getReturnType().equals(VoidType.v())) {
            returnStmt = Jimple.v().newReturnVoidStmt();
        } else {
            returnStmt = Jimple.v().newReturnStmt(getSimpleDefaultValue(returnType));
        }

        body.getUnits().add(returnStmt);

        return target;
    }

    public static Value getSimpleDefaultValue(Type t) {
        if (t == RefType.v("java.lang.String"))
            return StringConstant.v("");
        if (t instanceof CharType)
            return IntConstant.v(0);
        if (t instanceof ByteType)
            return IntConstant.v(0);
        if (t instanceof ShortType)
            return IntConstant.v(0);
        if (t instanceof IntType)
            return IntConstant.v(0);
        if (t instanceof FloatType)
            return FloatConstant.v(0);
        if (t instanceof LongType)
            return LongConstant.v(0);
        if (t instanceof DoubleType)
            return DoubleConstant.v(0);
        if (t instanceof BooleanType)
            return DIntConstant.v(0, BooleanType.v());

        // also for arrays etc.
        return NullConstant.v();
    }

}
