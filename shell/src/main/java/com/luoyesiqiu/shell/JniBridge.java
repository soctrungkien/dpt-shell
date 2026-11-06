package com.luoyesiqiu.shell;

import android.content.Context;
import android.util.Log;

import androidx.annotation.Keep;

import com.luoyesiqiu.shell.util.EnvUtils;

import java.io.File;

/**
 * Created by luoyesiqiu
 */
@Keep
public class JniBridge {
    private static final String TAG = "dpt_" + JniBridge.class.getSimpleName();
    public static native void craoc(String applicationClassName);
    public static native void ia();
    public static native String rcf();
    public static native void cbde(ClassLoader targetClassLoader);
    public static native void rde(ClassLoader classLoader,String elementName);
    public static native String gap();
    public static native String gdp();
    public static native Object ra(String originApplicationClassName);
    public static native String rapn();
    public static native void clinit();

    public static void loadShellLibs(String workspacePath) {
        final String[] allowLibNames = {Global.SHELL_SO_NAME};
        try {
            String abiDirName = EnvUtils.getAbiDirName();
            File shellLibsFile = new File(workspacePath + File.separator + Global.LIB_DIR + File.separator + abiDirName);
            File[] files = shellLibsFile.listFiles();
            boolean loaded = false;
            if(files != null) {
                for(File shellLibPath : files) {
                    String fullLibPath = shellLibPath.getAbsolutePath();
                    for(String libName : allowLibNames) {
                        String libSuffix = File.separator + libName;
                        if(fullLibPath.endsWith(libSuffix)) {
                            Log.d(TAG, "loadShellLibs: " + fullLibPath);
                            System.load(fullLibPath);
                            loaded = true;
                        }
                    }
                }
            }
            if(!loaded) {
                // Log.* is stripped by R8 (-assumenosideeffects), so use stderr to keep
                // this visible in logcat when the shell library cannot be found.
                System.err.println(TAG + ": shell lib not found: "
                        + new File(shellLibsFile, Global.SHELL_SO_NAME).getAbsolutePath());
            }
        }
        catch (Throwable e){
            // Keep the cause visible in logcat: Log.w is removed by R8 in release builds.
            e.printStackTrace();
            Log.w(TAG,e);
        }
    }

}
