package ca.utoronto.ece496.utils;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

/**
 * Created by Charlie on 07. 03 2019
 */
public class GeneralUtil {
    @SuppressWarnings("unchecked")
    public static <T, R> R accessField(Class<? extends T> clazz, String fieldName, T instance) {
        try {
            Field declaredField = clazz.getDeclaredField(fieldName);
            declaredField.setAccessible(true);
            return (R) declaredField.get(instance);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T, R> R invokeMethod(Class<? extends T> clazz, String methodName,
                                        List<Class<?>> paramTypes, List<?> params, T instance) {
        try {
            Method method = clazz.getDeclaredMethod(methodName, paramTypes.toArray(new Class[0]));
            method.setAccessible(true);
            return (R) method.invoke(instance, params.toArray(new Object[0]));
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }
}
