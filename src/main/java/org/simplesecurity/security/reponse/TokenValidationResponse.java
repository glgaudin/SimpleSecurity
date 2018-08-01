package org.simplesecurity.security.reponse;

import org.simplesecurity.security.SecuredUser;

public class TokenValidationResponse {
	
	private SecuredUser user;
	private String token;

	public TokenValidationResponse(String token, SecuredUser user) {
		setToken(token);
		setUser(user);
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
