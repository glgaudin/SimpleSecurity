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
package org.simplesecurity.security.service;

import javax.servlet.http.HttpServletResponse;

import org.simplesecurity.security.SecuredUser;
import org.simplesecurity.security.reponse.TokenValidationResponse;


/**
 * Security service that manages tokens and such for a user
 * 
 * Token contains the following information:
 * 
 *     user id, date/time token was issued
 * 
 * and is in the following format:
 * 
 *     RANDOM UUID^^DATE_TIME^^ID
 * 
 * @author G
 *
 */
public interface SecurityService {

	/**
	 * validates a user based on the supplied token
	 * @param httpResponse
	 * @param token
	 * @return
	 */
	
	boolean isValidUser(HttpServletResponse httpResponse, String token);	
	/**
	 * Gets a token for a user
	 * 
	 * @param user
	 * @return
	 */
	String getToken(SecuredUser user);
	
	/**
	 * Checks a token for validity and throws an exception if invalid
	 * 
	 * @param token
	 * @return user
	 */
	TokenValidationResponse validate(String token);
	
	/**
	 * Checks a token for validity and returns a renewed one, throws an exception if invalid
	 * 
	 * @param token
	 * @return
	 */
	TokenValidationResponse renew(String token);
	
	/**
	 * Checks creds and returns token if valid
	 * 
	 * @param userName
	 * @param password
	 * @return
	 */
	TokenValidationResponse login(String userName, String password) throws SecurityException;

	/**
	 * Encode the payload with the current key and key rotation strategy.
	 * 
	 * @param payload
	 * @return
	 */
	String encode(String payload);
	
	/**
	 * Hash a string with the current salt.
	 * 
	 * @param payload
	 * @return
	 */
	String hash(String payload);

	/**
	 * get the user matching the supplied id
	 * 
	 * @param id
	 * @return
	 */
	SecuredUser getUser(String id);

	/**
	 * get the user matching the supplied user name and password
	 * 
	 * @param userName
	 * @param encryptedPassword
	 * @return
	 */
	SecuredUser getUser(String userName, String encryptedPassword);
	
	
}
