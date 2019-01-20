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
    private static final String BASE_DIR = "/Users/Charlie/repos/ECE419/";

    @Test
    public void testRunFromCmdLine() throws Exception {
        FindBugs2.main(new String[] {
                "-sourcepath", BASE_DIR + String.join(File.separator, "src", "main", "java"),
                "-auxclasspath", BASE_DIR + "libs" + File.separator,
                BASE_DIR + "ecs.jar"
        });
    }
}
