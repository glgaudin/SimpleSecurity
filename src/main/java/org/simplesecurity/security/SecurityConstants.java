package org.simplesecurity.security;

/**
 * 
 * Security related constants
 *
 */
public interface SecurityConstants {

	public static final String HEADER_SECURITY_TOKEN = "X-Token";
	
	public static final String DELIMITER = "^^";
	
	public static final String DATETIME_FORMAT = "yyyy-MM-dd HH:mm:ss";
	
	public static final String INVALID_LOGIN = "Invalid login";
	
	public static final KeyAlgorithms KEY_ALGORITHM = KeyAlgorithms.AES;
	
	public static final Boolean FIXED_KEY_STRATEGY = Boolean.FALSE;

	public static final Boolean ROTATING_KEY_STRATEGY = Boolean.TRUE;
	
}
