package org.simplesecurity.security.context;

public class SecurityContext {

	private static final ThreadLocal<UserContext> contextContainer = new InheritableThreadLocal<>();

	public static UserContext getUserContext() {

		if (contextContainer.get() == null) {
			contextContainer.set(createUserContext());
		}

		return contextContainer.get();
	}

	public static void setUserContext(UserContext context) {
		if (context != null) {
			contextContainer.set(context);
		}
	}

	public static UserContext createUserContext() {
		return new UserContext();
	}
}