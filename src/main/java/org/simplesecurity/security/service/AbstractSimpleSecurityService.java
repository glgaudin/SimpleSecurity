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

import static org.simplesecurity.security.SecurityConstants.DATETIME_FORMAT;
import static org.simplesecurity.security.SecurityConstants.DELIMITER;
import static org.simplesecurity.security.SecurityConstants.HEADER_SECURITY_TOKEN;
import static org.simplesecurity.security.SecurityConstants.INVALID_LOGIN;
import static org.simplesecurity.security.SecurityConstants.KEY_ALGORITHM;
import static org.simplesecurity.security.SecurityConstants.SALT;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.simplesecurity.security.SecuredUser;
import org.simplesecurity.security.context.SecurityContext;
import org.simplesecurity.security.context.UserContext;
import org.simplesecurity.security.exception.EncryptionException;
import org.simplesecurity.security.exception.ExpiredTokenException;
import org.simplesecurity.security.exception.InvalidTokenException;
import org.simplesecurity.security.reponse.TokenValidationResponse;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
/**
 * EXAMPLE abstract security class providing a working mechanism
 * so we can demonstrate how the AspectJ join points work with the 
 * annotations to allow us to secure methods with annotations.  
 *  
 * Token contains the following information:
 * 
 *     user id, date/time token was issued
 * 
 * and is in the following format:
 * 
 *     DATE_TIME^^ID

 * @author glgau
 *
 */
public abstract class AbstractSimpleSecurityService implements SecurityService {

	private static final long EXPIRE_MILIS = TimeUnit.MINUTES.toMillis(10);
	
	private static final Key TOKEN_KEY = getRandonKey();
	
	/**
	 * Tests to see if the user is valid, and then: 
	 * - puts the new token in the response header
	 * - sets the user information on the security context
	 * 
	 * @param httpResponse
	 * @param token
	 * @return
	 */
	@Override
	public boolean isValidUser(HttpServletResponse httpResponse, String token) {

		// validate and add new token to response
		TokenValidationResponse validationResponse = doValidate(token);

		// set the user information in the security context
		SecurityContext.setUserContext(
				new UserContext(validationResponse.getUser(), validationResponse.getToken()));

		// add the token to the response
		httpResponse.addHeader(HEADER_SECURITY_TOKEN, validationResponse.getToken());
		
		return true;
	}
	
	/**
	 * Hash a value with the salt specified in the properties file
	 */
	public String hash(String value) {
		return doHash(value, SALT.getBytes());
	}
	
	@Override
	public TokenValidationResponse login(String userName, String password) throws SecurityException {

		// make sure we have the required info
		if (StringUtils.isEmpty(userName) || StringUtils.isEmpty(password)) {
			throw new SecurityException(INVALID_LOGIN);
		}
		
		// hash the password and get the user
		SecuredUser user = getUser(userName, hash(password));

		// return the token validation response
		return new TokenValidationResponse(getToken(user), user);		
	}

	@Override
	public String getToken(SecuredUser user) {
		return createSignedToken(createTokenPayload(user));
	}
	
	/**
	 * Get the payload from a signed JWT token
	 * 
	 * @param signedToken
	 * @return
	 */
	public final String getPayload(String signedToken) {
		return Jwts.parser().setSigningKey(TOKEN_KEY).parseClaimsJws(signedToken).getBody().getSubject();
	}
	
	/**
	 * Create a signed JWT token
	 * 
	 * @param payload
	 * @return
	 */
	protected final String createSignedToken(String payload) {
		return Jwts.builder().setSubject(payload).signWith(SignatureAlgorithm.HS512, TOKEN_KEY).compact();
	}
	
	protected String createTokenPayload(SecuredUser user) {

		String payload = null;
		
		// just use the expiration date and user id in the payload and only create it if there's a user 
		if (user != null && user.getId() != null) {
			payload = new SimpleDateFormat(DATETIME_FORMAT).format(new Date()) + DELIMITER + user.getId();
		}
		
		return payload;
		
	}
	
	private TokenValidationResponse doValidate(String jwtToken) {
		
		// check the date... it's always in the second position
		SecuredUser user = null;
		String id = null;
		String source = null;
		
		try {
			// get the payload from the token
			source = getPayload(jwtToken);

			// split it, the date is first and the id is second
			String[] sourceElements = StringUtils.split(source, DELIMITER);

			if (!doIsValid(sourceElements[0], EXPIRE_MILIS)) {
				throw new ExpiredTokenException("Expired token: " + source);
			}
			
			id = sourceElements[1];
			
		} catch (Exception e) {
			throw new InvalidTokenException("Invalid token: " + source);
		}
		
		// now make sure the user is valid
		if (id != null) {
			try {
		
				if (StringUtils.isNoneBlank(id)) {
					user = getUser(id);
				}
			} catch (Exception e) {
				// just set the user to null and fall through to an invalid login 
				user = null;
			}
		}
		
		if (user == null) {
			throw new SecurityException(INVALID_LOGIN);
		}

		// return the response with the user and the token
		return new TokenValidationResponse(getToken(user), user);
		
	}	
	
	private final boolean doIsValid(String source, long expireMillis) {
		// decrypt it
		Date tokenDate;
		try {
			tokenDate = new SimpleDateFormat(DATETIME_FORMAT).parse(source);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			throw new InvalidTokenException(e.getMessage());
		}
		// test the date
		return ((tokenDate.getTime() + expireMillis) > new Date().getTime());
	}
	
	private final String doHash(String payload, byte[] salt) {
		
		String hashedValue = null;
		
		try {
		
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			md.update(salt);
			
			byte[] bytes = md.digest(payload.getBytes());
			
			StringBuilder sb = new StringBuilder();
			
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			
			hashedValue = sb.toString();
			
		} catch (NoSuchAlgorithmException e) {
			throw new EncryptionException(e);
		}
		return hashedValue;
	}
	
	static Key getRandonKey() {
		SecureRandom random = new SecureRandom();		
		byte[] keyBytes = new byte[16];
		random.nextBytes(keyBytes);
		return new SecretKeySpec(keyBytes, KEY_ALGORITHM.toString());
	}
	
}
