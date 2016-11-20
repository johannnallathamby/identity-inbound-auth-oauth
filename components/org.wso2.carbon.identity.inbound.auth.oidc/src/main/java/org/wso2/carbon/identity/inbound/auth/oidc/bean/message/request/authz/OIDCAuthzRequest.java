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

package org.wso2.carbon.identity.inbound.auth.oidc.bean.message.request.authz;

import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.authz.OAuth2AuthzRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class OIDCAuthzRequest extends OAuth2AuthzRequest {

    private static final long serialVersionUID = -3009563708954787261L;

    protected String nonce;
    protected String display;
    protected String idTokenHint;
    protected String loginHint;
    protected Set<String> prompts;
    protected List<String> acrValues;
    protected boolean isLoginRequired = false;
    protected boolean isConsentRequired = false;
    protected boolean isPromptNone = false;

    protected OIDCAuthzRequest(OIDCAuthzRequestBuilder builder) {
        super(builder);
        this.nonce = builder.nonce;
        this.display = builder.display;
        this.idTokenHint = builder.idTokenHint;
        this.loginHint = builder.loginHint;
        this.prompts = builder.prompts;
        this.isLoginRequired = builder.isLoginRequired;
        this.isConsentRequired = builder.isConsentRequired;
        this.isPromptNone = builder.isPromptNone;
    }

    public String getNonce() {
        return nonce;
    }

    public String getDisplay() {
        return display;
    }

    public String getIdTokenHint() {
        return idTokenHint;
    }

    public String getLoginHint() {
        return loginHint;
    }

    public Set<String> getPrompts() {
        return prompts;
    }

    public List<String> getAcrValues() {
        return acrValues;
    }

    public boolean isLoginRequired() {
        return this.isLoginRequired;
    }

    public boolean isConsentRequired() {
        return this.isConsentRequired;
    }

    public boolean isPromptNone() {
        return this.isPromptNone;
    }

    public static class OIDCAuthzRequestBuilder extends AuthzRequestBuilder {

        protected String nonce;
        protected String display;
        protected String idTokenHint;
        protected String loginHint;
        protected Set<String> prompts = new HashSet<>();
        protected List<String> acrValues = new ArrayList();
        protected boolean isLoginRequired = false;
        protected boolean isConsentRequired = false;
        protected boolean isPromptNone = false;

        public OIDCAuthzRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public OIDCAuthzRequestBuilder() {

        }

        public OIDCAuthzRequestBuilder setNonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public OIDCAuthzRequestBuilder setDisplay(String display) {
            this.display = display;
            return this;
        }

        public OIDCAuthzRequestBuilder setIdTokenHint(String idTokenHint) {
            this.idTokenHint = idTokenHint;
            return this;
        }

        public OIDCAuthzRequestBuilder setLoginHint(String loginHint) {
            this.loginHint = loginHint;
            return this;
        }

        public OIDCAuthzRequestBuilder setPrompts(Set<String> prompts) {
            this.prompts = prompts;
            return this;
        }

        public OIDCAuthzRequestBuilder addPrompt(String prompt) {
            this.prompts.add(prompt);
            return this;
        }

        public OIDCAuthzRequestBuilder setAcrValues(List<String> acrValues) {
            this.acrValues = acrValues;
            return this;
        }

        public OIDCAuthzRequestBuilder addAcrValue(String acrValue) {
            this.acrValues.add(acrValue);
            return this;
        }

        public OIDCAuthzRequestBuilder setLoginRequired(boolean isLoginRequired) {
            this.isLoginRequired = isLoginRequired;
            return this;
        }

        public OIDCAuthzRequestBuilder setConsentRequired(boolean isConsentRequired) {
            this.isConsentRequired = isConsentRequired;
            return this;
        }

        public OIDCAuthzRequestBuilder setPromptNone(boolean isPromptNone) {
            this.isPromptNone = isPromptNone;
            return this;
        }

        public OIDCAuthzRequest build() {
            return new OIDCAuthzRequest(this);
        }

    }
}
