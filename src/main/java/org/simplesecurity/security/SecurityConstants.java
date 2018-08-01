package org.simplesecurity.security;

import org.springframework.beans.factory.annotation.Value;

/**
 * 
 * Security related constants
 *
 */
public class SecurityConstants {
	
    @Value("${security.securitytoken}")
	public static String HEADER_SECURITY_TOKEN;
	
    @Value("${security.delimiter}")
	public static String DELIMITER;
	
    @Value("${security.datetimeformat}")
	public static String DATETIME_FORMAT;
	
    @Value("${security.keystrategy}")
	public static Boolean KEY_STRATEGY;
	
    @Value("${security.msg.invalidlogin}")
	public static String INVALID_LOGIN;
	
    @Value("${security.msg.invaliduser}")
	public static String INVALID_USER;

    @Value("${security.msg.nopermission}")
	public static String NO_PERMISSION;

    @Value("${security.msg.invalidpermission}")
	public static String INVALID_PERMISSION;

    @Value("${security.salt}")
	public static String SALT;

    public static KeyAlgorithms KEY_ALGORITHM = KeyAlgorithms.AES;
	
	public static Boolean FIXED_KEY_STRATEGY = Boolean.FALSE;

	public static Boolean ROTATING_KEY_STRATEGY = Boolean.TRUE;
	
}
