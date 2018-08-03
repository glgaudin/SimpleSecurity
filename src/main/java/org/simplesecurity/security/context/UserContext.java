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
package org.simplesecurity.security.context;

import org.simplesecurity.security.SecuredUser;
import org.simplesecurity.security.SecuredUserPermission;
import org.simplesecurity.security.exception.PermissionException;
import static org.simplesecurity.security.SecurityConstants.INVALID_USER;
import static org.simplesecurity.security.SecurityConstants.NO_PERMISSION;

import org.apache.commons.lang3.StringUtils;

import static org.simplesecurity.security.SecurityConstants.INVALID_PERMISSION;;
/**
 * User context class to be stored in the SecurityContext
 * 
 * @author glgau
 *
 */
public class UserContext {

	private SecuredUser user;
	private String token;

	/**
	 * no-arg constructor
	 */
	public UserContext() {
	}
	
	/**
	 * Constructor accepting a secured user
	 * 
	 * @param user
	 */
	public UserContext(SecuredUser user) {
		this.user = user;
	}

	/**
	 * Constructor accepting a secured user and a token
	 * 
	 * @param user
	 * @param token
	 */
	public UserContext(SecuredUser user, String token) {
		this.user = user;
		this.token = token;
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
	
	/**
	 * check to see if the user has the supplied permission
	 * 
	 * @param permission
	 */
	public void hasPermission(String permission) {

		// no permission requested
		if (StringUtils.isBlank(permission)) {
			throw new PermissionException(INVALID_PERMISSION);
		}
		// no user in context
		if (user == null) {
			throw new SecurityException(INVALID_USER);
		}

		// user has no permissions
		if (user.getUserPermissions() == null || user.getUserPermissions().size() < 1) {
			throw new PermissionException(NO_PERMISSION);
		}
		
		// check the permissions
		for (SecuredUserPermission p: user.getUserPermissions()) {
			if (p != null && permission.equals(p.getPermission())) {
				return;
			}
		}

		// user does not have the permission requested
		throw new PermissionException(NO_PERMISSION);
	}
}
