package ca.utoronto.ece496.utils;

import java.lang.reflect.Field;

/**
 * Created by Charlie on 07. 03 2019
 */
public class GeneralUtil {
    @SuppressWarnings("unchecked")
    public static <T, R>  R accessField(Class<T> clazz, String fieldName, T instance) {
        try {
            Field declaredField = clazz.getDeclaredField(fieldName);
            declaredField.setAccessible(true);
            return (R) declaredField.get(instance);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
}
