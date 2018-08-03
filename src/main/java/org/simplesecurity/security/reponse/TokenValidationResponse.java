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
package org.simplesecurity.security.reponse;

import org.simplesecurity.security.SecuredUser;
/**
 * response dto representing the user and their token 
 * 
 * @author glgau
 *
 */
public class TokenValidationResponse {
	
	private SecuredUser user;
	private String token;

	/**
	 * constructor accepting a user and token
	 * 
	 * @param token
	 * @param user
	 */
	public TokenValidationResponse(String token, SecuredUser user) {
		setToken(token);
		setUser(user);
	}

	/**
	 * return the user
	 * 
	 * @return
	 */
	public SecuredUser getUser() {
		return user;
	}

	/**
	 * set the user
	 * 
	 * @param user
	 */
	public void setUser(SecuredUser user) {
		this.user = user;
	}
	
	/**
	 * return the token
	 * 
	 * @return
	 */
	public String getToken() {
		return token;
	}

	/**
	 * set the token
	 * 
	 * @param token
	 */
	public void setToken(String token) {
		this.token = token;
	}
	
}
