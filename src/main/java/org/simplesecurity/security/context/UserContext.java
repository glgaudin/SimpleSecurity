package org.simplesecurity.security.context;

import org.simplesecurity.security.SecuredUser;
import org.simplesecurity.security.SecuredUserAuthority;
import org.simplesecurity.security.exception.PermissionException;
import static org.simplesecurity.security.SecurityConstants.INVALID_USER;
import static org.simplesecurity.security.SecurityConstants.NO_PERMISSION;

import org.apache.commons.lang3.StringUtils;

import static org.simplesecurity.security.SecurityConstants.INVALID_PERMISSION;;

public class UserContext {

	private SecuredUser user;
	private String token;

	public UserContext() {
	}
	
	public UserContext(SecuredUser user) {
		this.user = user;
	}

	public UserContext(SecuredUser user, String token) {
		this.user = user;
		this.token = token;
	}

	public SecuredUser getUser() {
		return user;
	}

	public void setUser(SecuredUser user) {
		this.user = user;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}
	
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
		if (user.getUserAuthorities() == null || user.getUserAuthorities().size() < 1) {
			throw new PermissionException(NO_PERMISSION);
		}
		
		// check the permissions
		for (SecuredUserAuthority auth: user.getUserAuthorities()) {
			if (auth != null && permission.equals(auth.getAuthority())) {
				return;
			}
		}

		// user does not have the permission requested
		throw new PermissionException(NO_PERMISSION);
	}
}
