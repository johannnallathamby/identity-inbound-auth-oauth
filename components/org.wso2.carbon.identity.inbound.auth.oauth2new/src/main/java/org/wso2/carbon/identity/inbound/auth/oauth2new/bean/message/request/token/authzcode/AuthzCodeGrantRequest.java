/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.authzcode;

import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.OAuth2TokenRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthzCodeGrantRequest extends OAuth2TokenRequest {

    private static final long serialVersionUID = -7079593227614826792L;

    private String code;
    private String redirectURI;
    private String pkceCodeVerifier;

    protected AuthzCodeGrantRequest(AuthzCodeGrantBuilder builder) {
        super(builder);
        this.code = builder.code;
        this.redirectURI = builder.redirectURI;
        this.pkceCodeVerifier = builder.pkceCodeVerifier;
    }

    public String getCode() {
        return code;
    }

    public String getRedirectURI() {
        return redirectURI;
    }

    public String getPKCECodeVerifier() {
        return pkceCodeVerifier;
    }

    public static class AuthzCodeGrantBuilder extends TokenRequestBuilder {

        private String code;
        private String redirectURI;
        private String pkceCodeVerifier;

        public AuthzCodeGrantBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public AuthzCodeGrantBuilder() {
        }

        public AuthzCodeGrantBuilder setCode(String code) {
            this.code = code;
            return this;
        }

        public AuthzCodeGrantBuilder setRedirectURI(String redirectURI) {
            this.redirectURI = redirectURI;
            return this;
        }

        public AuthzCodeGrantBuilder setPKCECodeVerifier(String pkceCodeVerifier) {
            this.pkceCodeVerifier = pkceCodeVerifier;
            return this;
        }

        @Override
        public AuthzCodeGrantRequest build() {
            return new AuthzCodeGrantRequest(this);
        }
    }
}
