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

package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.OAuth2IdentityRequest;

public class TokenRequest extends OAuth2IdentityRequest {

    private static final long serialVersionUID = 2113773120127290578L;

    private String grantType;

    protected TokenRequest(TokenRequestBuilder builder) throws FrameworkClientException {
        super(builder);
        this.grantType = builder.grantType;
    }

    public String getGrantType() {
        return grantType;
    }

    public static class TokenRequestBuilder extends OAuth2IdentityRequestBuilder {

        private String grantType;

        public TokenRequestBuilder setGrantType(String grantType) {
            this.grantType = grantType;
            return this;
        }

        public TokenRequest build() throws FrameworkClientException {
            return new TokenRequest(this);
        }
    }
}
