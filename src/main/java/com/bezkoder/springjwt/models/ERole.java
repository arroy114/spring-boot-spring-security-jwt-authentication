package com.bezkoder.springjwt.models;

public enum ERole {

    //Has to use prefix ROLE_ because in class SecurityExpressionRoot, private String defaultRolePrefix = "ROLE_";
    ROLE_USER,
    ROLE_MODERATOR,
    ROLE_ADMIN
}
