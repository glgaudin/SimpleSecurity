package org.simplesecurity.security.service;

import static org.simplesecurity.security.SecurityConstants.DATETIME_FORMAT;
import static org.simplesecurity.security.SecurityConstants.DELIMITER;
import static org.simplesecurity.security.SecurityConstants.HEADER_SECURITY_TOKEN;
import static org.simplesecurity.security.SecurityConstants.INVALID_LOGIN;
import static org.simplesecurity.security.SecurityConstants.KEY_ALGORITHM;
import static org.simplesecurity.security.SecurityConstants.SALT;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.simplesecurity.security.SecuredUser;
import org.simplesecurity.security.context.SecurityContext;
import org.simplesecurity.security.context.UserContext;
import org.simplesecurity.security.exception.DecryptionException;
import org.simplesecurity.security.exception.EncryptionException;
import org.simplesecurity.security.exception.ExpiredTokenException;
import org.simplesecurity.security.exception.InvalidTokenException;
import org.simplesecurity.security.reponse.TokenValidationResponse;
import org.simplesecurity.security.SecurityUtil;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public abstract class AbstractSecurityService implements SecurityService {

	private final static Logger LOGGER = Logger.getLogger(AbstractSecurityService.class);
	
	private static final long EXPIRE_MILIS = TimeUnit.MINUTES.toMillis(10);
	
	private static final Key AES_KEY = SecurityUtil.getRandonKey();
	private static final Key TOKEN_KEY = SecurityUtil.getRandonKey();
	
	public AbstractSecurityService() {
		super();
	}

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
		return createSignedToken(encode(createTokenPayload(user)));
	}
	
	@Override
	public TokenValidationResponse renew(String token) {
		SecuredUser user = doValidate(token);

		if (user == null) {
			throw new SecurityException(INVALID_LOGIN);
		}
		
		return createValidationResponse(user);
	}

	@Override
	public String encode(String payload) {
		return doEncode(payload, AES_KEY);
	}
	
	/**
	 * Decode the payload with the current key and key rotation strategy 
	 * 
	 * @param payload
	 * @return
	 */
	public String decode(String payload) {
		
		return doDecode(payload, AES_KEY);
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
	
	abstract SecuredUser getUser(String id);

	abstract SecuredUser getUser(String userName, String encryptedPassword);
	
	private SecuredUser doValidate(String jwtToken) {
		
		// check the date... it's always in the second position
		SecuredUser user = null;
		String id = null;
		String token = null;
		
		try {
			token = getPayload(jwtToken);

			// decrypt it - token ends up as UUID^^DATE_TIME^^ID
			String source = decode(token);
			String[] sourceElements = StringUtils.split(source, DELIMITER);
			
			id = sourceElements[2];
			if (!isValid(sourceElements, EXPIRE_MILIS)) {
				throw new ExpiredTokenException("Expired token: " + token);
			}
		} catch (Exception e) {
			throw new InvalidTokenException("Invalid token: " + token);
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
	
	private String createTokenPayload(SecuredUser user) {
		// remove nulls and add delimiters
		// just use the user id in the payload... 
		String payload = null;
		if (user != null && user.getId() != null) {
			payload = UUID.randomUUID().toString() + DELIMITER + // just push the date over one place so we always know where it is 
					new SimpleDateFormat(DATETIME_FORMAT).format(new Date()) + DELIMITER + user.getId();  //TODO: change to timestamp
		}
		
		return payload;
		
	}
	
	private TokenValidationResponse createValidationResponse(SecuredUser user) {
		return new TokenValidationResponse(getToken(user), user);
	}
	

	private final String doEncode(String payload, Key key) {
		
		try {
			Cipher cipher = Cipher.getInstance(KEY_ALGORITHM.toString());
			cipher.init(Cipher.ENCRYPT_MODE, key);
			
			return Base64.getEncoder().encodeToString(cipher.doFinal(payload.getBytes()));
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | 
				IllegalBlockSizeException | InvalidKeyException |
				BadPaddingException e) {
			throw new EncryptionException("Encryption error: " + e.getMessage());
		}
	}
	
	private final String doDecode(String payload, Key key) {
		try {
			Cipher cipher = Cipher.getInstance(KEY_ALGORITHM.toString());
			cipher.init(Cipher.DECRYPT_MODE, key);
			return new String(cipher.doFinal(Base64.getDecoder().decode(payload)));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | 
				IllegalBlockSizeException | InvalidKeyException |
				BadPaddingException e) {
			
			throw new DecryptionException("Decryption error: " + e.getMessage());
		}
	}
	
	private final String doCreateSignedToken(String payload, Key key) {
		return Jwts.builder().setSubject(payload).signWith(SignatureAlgorithm.HS512, key).compact();
	}
	
	private final String getJwtPayload(String signedToken, Key key) {
		// this should blow an exception if the key is invalid
		return Jwts.parser().setSigningKey(key).parseClaimsJws(signedToken).getBody().getSubject();
	}
	
	private final boolean isValid(String[] sourceElements, long expireMillis) {
		// decrypt it
		Date tokenDate;
		try {
			tokenDate = new SimpleDateFormat(DATETIME_FORMAT).parse(sourceElements[1]);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			throw new RuntimeException(e.getMessage());
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
	
}
