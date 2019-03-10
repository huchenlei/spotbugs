package ca.utoronto.ece496.utils;

import edu.umd.cs.findbugs.FindBugs2;
import org.junit.Test;

import java.io.File;

/**
 * This test file is used for debugging purpose
 *
 * Created by Charlie on 19. 01 2019
 */
public class DebugTest {
    private static final String BASE_DIR = "/Users/Charlie/repos/flowdroid-experiment/spring_sample_apps/";

    @Test
    public void testRunFromCmdLine() throws Exception {
        FindBugs2.main(new String[] {
                "-sourcepath", BASE_DIR + String.join(File.separator, "src", "main", "java"),
                "-auxclasspath", BASE_DIR + String.join(File.separator, "build", "libs", "exp-spring-boot-0.1.0", "BOOT-INF", "lib"),
                BASE_DIR + String.join(File.separator, "build", "libs", "exp-spring-boot-0.1.0", "BOOT-INF", "classes")
        });
    }
}
