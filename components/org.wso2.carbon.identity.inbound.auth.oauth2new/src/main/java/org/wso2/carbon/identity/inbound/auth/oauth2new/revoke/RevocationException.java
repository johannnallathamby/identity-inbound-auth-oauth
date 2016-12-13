package org.wso2.carbon.identity.inbound.auth.oauth2new.revoke;

import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2Exception;

public class RevocationException extends OAuth2Exception {

    protected RevocationException(String errorDescription) {
        super(errorDescription);
    }

    protected RevocationException(String errorDescription, Throwable cause) {
        super(errorDescription, cause);
    }

    public static RevocationException error(String errorDescription){
        return new RevocationException(errorDescription);
    }

    public static RevocationException error(String errorDescription, Throwable cause){
        return new RevocationException(errorDescription, cause);
    }
}
