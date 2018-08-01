package org.simplesecurity.security.exception;
/**
 * Thrown when a decryption error occurs
 *
 */
public class PermissionException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public PermissionException() {
		super();
	}

	public PermissionException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public PermissionException(String message, Throwable cause) {
		super(message, cause);
	}

	public PermissionException(String message) {
		super(message);
	}

	public PermissionException(Throwable cause) {
		super(cause);
	}

}
