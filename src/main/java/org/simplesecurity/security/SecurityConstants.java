/*
 * Copyright (C) 2018 Gregg Gaudin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */
package org.simplesecurity.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 
 * Security related constants
 *
 */
@Component
public class SecurityConstants {

	public static String HEADER_SECURITY_TOKEN;

	@Value("${security.securitytoken}")
	public void setSecurityToken(String value) {
		HEADER_SECURITY_TOKEN = value;
	}

	public static String DELIMITER;

	@Value("${security.delimiter}")
	public void setDelimiter(String value) {
		DELIMITER = value;
	}

	public static String DATETIME_FORMAT;

	@Value("${security.datetimeformat}")
	public void setDateFormat(String value) {
		DATETIME_FORMAT = value;
	}

	public static Boolean KEY_STRATEGY;

	@Value("${security.keystrategy}")
	public void setKeyStrategy(Boolean value) {
		KEY_STRATEGY = value;
	}

	public static String INVALID_LOGIN;

	@Value("${security.msg.invalidlogin}")
	public void setInvalidLogin(String value) {
		INVALID_LOGIN = value;
	}

	public static String INVALID_USER;

	@Value("${security.msg.invaliduser}")
	public void setInvaliduser(String value) {
		INVALID_USER = value;
	}

	public static String NO_PERMISSION;

	@Value("${security.msg.nopermission}")
	public void setNoPermission(String value) {
		NO_PERMISSION = value;
	}

	public static String INVALID_PERMISSION;

	@Value("${security.msg.invalidpermission}")
	public void setInvalidPermission(String value) {
		INVALID_PERMISSION = value;
	}

	public static String SALT;

	@Value("${security.salt}")
	public void setSalt(String value) {
		SALT = value;
	}

	public static KeyAlgorithms KEY_ALGORITHM = KeyAlgorithms.AES;

	public static Boolean FIXED_KEY_STRATEGY = Boolean.FALSE;

	public static Boolean ROTATING_KEY_STRATEGY = Boolean.TRUE;

}
