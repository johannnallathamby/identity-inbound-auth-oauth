package org.wso2.carbon.identity.inbound.auth.oidc.exception;

import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2AuthnException;

public class AccessTokenValidationException extends OAuth2AuthnException {

    protected AccessTokenValidationException(String errorDescription) {
        super(errorDescription);
    }

    protected AccessTokenValidationException(String errorDescription, Throwable cause) {
        super(errorDescription, cause);
    }

    public static AccessTokenValidationException error(String errorDescription){
        return new AccessTokenValidationException(errorDescription);
    }

    public static AccessTokenValidationException error(String errorDescription, Throwable cause){
        return new AccessTokenValidationException(errorDescription, cause);
    }
}
