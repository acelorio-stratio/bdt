package com.stratio.qa.utils;

public enum LdapUtil {
    INSTANCE;

    private final LdapUtils ldapUtils = new LdapUtils();

    public LdapUtils getldapUtils() {
        return ldapUtils;
    }
}
