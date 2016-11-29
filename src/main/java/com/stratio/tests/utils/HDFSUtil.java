package com.stratio.tests.utils;

public enum HDFSUtil {
    INSTANCE;

    private final HDFSUtils hdfsUtils = new HDFSUtils();

    public HDFSUtils getHDFSUtils() {
        return hdfsUtils;
    }

}