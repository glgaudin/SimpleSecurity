package org.simplesecurity.security.context;

import org.simplesecurity.security.SecuredUser;

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
}
