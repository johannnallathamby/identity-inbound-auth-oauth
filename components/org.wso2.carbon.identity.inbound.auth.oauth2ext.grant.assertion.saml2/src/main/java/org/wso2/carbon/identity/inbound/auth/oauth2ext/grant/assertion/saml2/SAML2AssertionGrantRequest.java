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

package org.wso2.carbon.identity.inbound.auth.oauth2ext.grant.assertion.saml2;

import org.opensaml.saml2.core.Assertion;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.TokenRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.Set;

public class SAML2AssertionGrantRequest extends TokenRequest {

    private static final long serialVersionUID = -4197423839037643097L;

    private Assertion assertion;
    private String assertionType;
    private Set<String> scopes = new HashSet();

    protected SAML2AssertionGrantRequest(SAML2AssertionGrantBuilder builder) throws FrameworkClientException {
        super(builder);
        this.assertion = builder.assertion;
        this.assertionType = builder.assertionType;
        this.scopes = builder.scopes;
    }

    public Assertion getAssertion() {
        return assertion;
    }

    public String getAssertionType() {
        return assertionType;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public static class SAML2AssertionGrantBuilder extends TokenRequestBuilder {

        private Assertion assertion;
        private String assertionType;
        private Set<String> scopes;

        public SAML2AssertionGrantBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public SAML2AssertionGrantBuilder setAssertion(Assertion assertion) {
            this.assertion = assertion;
            return this;
        }

        public SAML2AssertionGrantBuilder setAssertionType(String assertionType) {
            this.assertionType = assertionType;
            return this;
        }

        public SAML2AssertionGrantBuilder setScopes(Set<String> scopes) {
            this.scopes = scopes;
            return this;
        }

        @Override
        public SAML2AssertionGrantRequest build() throws FrameworkClientException {
            return new SAML2AssertionGrantRequest(this);
        }
    }
}
