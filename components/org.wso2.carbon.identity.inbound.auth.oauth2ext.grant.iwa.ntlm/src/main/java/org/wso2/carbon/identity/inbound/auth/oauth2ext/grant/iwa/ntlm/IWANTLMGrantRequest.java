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

package org.wso2.carbon.identity.inbound.auth.oauth2ext.grant.iwa.ntlm;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.TokenRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.Set;

public class IWANTLMGrantRequest extends TokenRequest {

    private static final long serialVersionUID = 8177989119965121010L;

    protected String windowsToken;
    protected Set<String> scopes = new HashSet<>();

    protected IWANTLMGrantRequest(IWANTLMGrantBuilder builder) throws FrameworkClientException {
        super(builder);
        this.windowsToken = builder.windowsToken;
        this.scopes = builder.scopes;
    }

    public String getWindowsToken() {
        return windowsToken;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public static class IWANTLMGrantBuilder extends TokenRequestBuilder {

        protected String windowsToken;
        protected Set<String> scopes;

        public IWANTLMGrantBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public IWANTLMGrantBuilder setWindowsToken(String windowsToken) {
            this.windowsToken = windowsToken;
            return this;
        }

        public IWANTLMGrantBuilder setScopes(Set<String> scopes) {
            this.scopes = scopes;
            return this;
        }

        @Override
        public IWANTLMGrantRequest build() throws FrameworkClientException {
            return new IWANTLMGrantRequest(this);
        }
    }
}
