package org.p16.planted;

import com.google.gson.Gson;
import org.apache.commons.lang3.StringUtils;

/** Minimal class so the shaded JAR references both bundled libraries. Never executed in the study. */
public final class Demo {
    private Demo() {}

    public static void main(String[] args) {
        System.out.println(new Gson().toJson(StringUtils.capitalize("planted")));
    }
}
