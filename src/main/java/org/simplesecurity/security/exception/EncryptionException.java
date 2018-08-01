package org.simplesecurity.security.exception;

/**
 * Thrown when a encryption error occurs
 *
 */
public class EncryptionException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public EncryptionException() {
		super();
	}

	public EncryptionException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public EncryptionException(String message, Throwable cause) {
		super(message, cause);
	}

	public EncryptionException(String message) {
		super(message);
	}

	public EncryptionException(Throwable cause) {
		super(cause);
	}

}
