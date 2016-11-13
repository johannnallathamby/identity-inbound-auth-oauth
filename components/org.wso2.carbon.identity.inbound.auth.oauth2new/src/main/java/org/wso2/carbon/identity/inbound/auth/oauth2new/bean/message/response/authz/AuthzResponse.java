package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz;

import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;


public class AuthzResponse extends ROApprovalResponse {

    private OAuthASResponse.OAuthAuthorizationResponseBuilder builder;

    protected AuthzResponse(IdentityResponseBuilder builder) {
        super(builder);
        this.builder = ((AuthzResponseBuilder)builder).builder;
    }

    public OAuthASResponse.OAuthAuthorizationResponseBuilder getBuilder() {
        return this.builder;
    }

    public static class AuthzResponseBuilder extends ROApprovalResponseBuilder {

        public AuthzResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        private OAuthASResponse.OAuthAuthorizationResponseBuilder builder;

        public OAuthASResponse.OAuthAuthorizationResponseBuilder getBuilder() {
            return builder;
        }

        public AuthzResponseBuilder setOLTUAuthzResponseBuilder(OAuthASResponse.OAuthAuthorizationResponseBuilder
                                                                        builder) {
            this.builder = builder;
            return this;
        }

        public AuthzResponse build() {
            return new AuthzResponse(this);
        }
    }
}
