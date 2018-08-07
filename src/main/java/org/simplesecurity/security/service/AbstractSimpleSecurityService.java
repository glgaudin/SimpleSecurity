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
import org.apache.log4j.Logger;
import org.simplesecurity.security.SecuredUser;
import org.simplesecurity.security.context.SecurityContext;
import org.simplesecurity.security.context.UserContext;
import org.simplesecurity.security.exception.ExpiredTokenException;
import org.simplesecurity.security.exception.InvalidTokenException;
import org.simplesecurity.security.reponse.TokenValidationResponse;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
/**
 * Abstract example class of some basic security concepts.  
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

	private final static Logger LOGGER = Logger.getLogger(AbstractSimpleSecurityService.class);
	
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
		TokenValidationResponse validationResponse = validate(token);

		SecurityContext.setUserContext(
				new UserContext(validationResponse.getUser(), validationResponse.getToken()));

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
	public TokenValidationResponse validate(String token) {

		SecuredUser user = doValidate(token);
		
		if (user == null) {
			throw new SecurityException(INVALID_LOGIN);
		}

		return createValidationResponse(user);
	}

	@Override
	public TokenValidationResponse login(String userName, String password) throws SecurityException {
		 // TODO: Placeholder. This needs to be thought out a bit. 
		
		if (StringUtils.isEmpty(userName) || StringUtils.isEmpty(password)) {
			throw new SecurityException(INVALID_LOGIN);
		}
		
		String encryptedPassword = hash(password);
		SecuredUser user = getUser(userName, encryptedPassword);

		return createValidationResponse(user);
		
	}

	@Override
	public String getToken(SecuredUser user) {
		return createSignedToken(createTokenPayload(user));
	}
	
	@Override
	public TokenValidationResponse renew(String token) {
		SecuredUser user = doValidate(token);

		if (user == null) {
			throw new SecurityException(INVALID_LOGIN);
		}
		
		return createValidationResponse(user);
	}

	/**
	 * Create a signed JWT token
	 * 
	 * @param payload
	 * @return
	 */
	public final String createSignedToken(String payload) {
		return doCreateSignedToken(payload, TOKEN_KEY);
	}
	
	/**
	 * Get the payload from a signed JWT token
	 * 
	 * @param signedToken
	 * @return
	 */
	public final String getPayload(String signedToken) {
		return getJwtPayload(signedToken, TOKEN_KEY);
	}
	
	protected String createTokenPayload(SecuredUser user) {
		// remove nulls and add delimiters
		// just use the user id in the payload... 
		String payload = null;
		if (user != null && user.getId() != null) {
			payload = new SimpleDateFormat(DATETIME_FORMAT).format(new Date()) + DELIMITER + user.getId();
		}
		
		return payload;
		
	}
	
	private SecuredUser doValidate(String jwtToken) {
		
		// check the date... it's always in the second position
		SecuredUser user = null;
		String id = null;
		String source = null;
		
		try {
			source = getPayload(jwtToken);

			String[] sourceElements = StringUtils.split(source, DELIMITER);

			if (!isValid(sourceElements[0], EXPIRE_MILIS)) {
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
		
		return user;
	}	
	
	private TokenValidationResponse createValidationResponse(SecuredUser user) {
		return new TokenValidationResponse(getToken(user), user);
	}
	

	private final String doCreateSignedToken(String payload, Key key) {
		return Jwts.builder().setSubject(payload).signWith(SignatureAlgorithm.HS512, key).compact();
	}
	
	private final String getJwtPayload(String signedToken, Key key) {
		// this should blow an exception if the key is invalid
		return Jwts.parser().setSigningKey(key).parseClaimsJws(signedToken).getBody().getSubject();
	}
	
	private final boolean isValid(String source, long expireMillis) {
		// decrypt it
		Date tokenDate;
		try {
			tokenDate = new SimpleDateFormat(DATETIME_FORMAT).parse(source);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			throw new InvalidTokenException(e.getMessage());
		}
		
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
			LOGGER.error(e);
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
