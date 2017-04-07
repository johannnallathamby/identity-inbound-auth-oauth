/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.authz;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.OAuth2IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.Set;

public class AuthzRequest extends OAuth2IdentityRequest {

    private static final long serialVersionUID = -7566583749113286264L;

    protected String responseType;
    protected String clientId;
    protected String redirectURI;
    protected String state;
    protected Set<String> scopes = new HashSet();
    protected String pkceCodeChallenge;
    protected String pkceCodeChallengeMethod;

    protected AuthzRequest(AuthzRequestBuilder builder) throws FrameworkClientException {
        super(builder);
        this.responseType = builder.responseType;
        this.clientId = builder.clientId;
        this.redirectURI = builder.redirectURI;
        this.state = builder.state;
        this.scopes = builder.scopes;
        this.pkceCodeChallenge = builder.pkceCodeChallenge;
        this.pkceCodeChallengeMethod = builder.pkceCodeChallengeMethod;
    }

    public String getResponseType() {
        return responseType;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectURI() {
        return redirectURI;
    }

    public String getState() {
        return state;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public String getPkceCodeChallenge() {
        return pkceCodeChallenge;
    }

    public String getPkceCodeChallengeMethod() {
        return pkceCodeChallengeMethod;
    }

    public static class AuthzRequestBuilder extends OAuth2IdentityRequestBuilder {

        protected String responseType;
        protected String clientId;
        protected String redirectURI;
        protected String state;
        protected Set<String> scopes = new HashSet();
        protected String pkceCodeChallenge;
        protected String pkceCodeChallengeMethod;

        public AuthzRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public AuthzRequestBuilder() {

        }

        public AuthzRequestBuilder setResponseType(String responseType) {
            this.responseType = responseType;
            return this;
        }

        public AuthzRequestBuilder setClientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public AuthzRequestBuilder setRedirectURI(String redirectURI) {
            this.redirectURI = redirectURI;
            return this;
        }

        public AuthzRequestBuilder setState(String state) {
            this.state = state;
            return this;
        }

        public AuthzRequestBuilder setScopes(Set<String> scopes) {
            this.scopes = scopes;
            return this;
        }

        public AuthzRequestBuilder addScope(String scope) {
            this.scopes.add(scope);
            return this;
        }

        public AuthzRequestBuilder setPkceCodeChallenge(String pkceCodeChallenge) {
            this.pkceCodeChallenge = pkceCodeChallenge;
            return this;
        }

        public AuthzRequestBuilder setPkceCodeChallengeMethod(String pkceCodeChallengeMethod) {
            this.pkceCodeChallengeMethod = pkceCodeChallengeMethod;
            return this;
        }

        public AuthzRequest build() throws FrameworkClientException {
            return new AuthzRequest(this);
        }
    }

}
