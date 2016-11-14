package org.wso2.carbon.identity.inbound.auth.oauth2new.model;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.io.Serializable;

public class UserConsent implements Serializable {

    private static final long serialVersionUID = -4853807491189397416L;

    private AuthenticatedUser authzUser;
    private int applicationId;
    private boolean isTrustedAlways;

    public UserConsent(AuthenticatedUser authzUser, int applicationId, boolean isTrustedAlways) {
        this.authzUser = authzUser;
        this.applicationId = applicationId;
        this.isTrustedAlways = isTrustedAlways;
    }

    public AuthenticatedUser getAuthzUser() {
        return authzUser;
    }

    public int getApplicationId() {
        return applicationId;
    }

    public boolean isTrustedAlways() {
        return isTrustedAlways;
    }

}
