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

package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.token;

import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;

public class TokenResponse extends IdentityResponse {

    private static final long serialVersionUID = -5294873717285750996L;

    protected OAuthASResponse.OAuthTokenResponseBuilder oltuTokenBuilder;

    public OAuthASResponse.OAuthTokenResponseBuilder getOltuTokenBuilder() {
        return oltuTokenBuilder;
    }

    protected TokenResponse(TokenResponseBuilder oltuTokenBuilder) {
        super(oltuTokenBuilder);
        this.oltuTokenBuilder = oltuTokenBuilder.oltuTokenBuilder;
    }

    public static class TokenResponseBuilder extends IdentityResponseBuilder {

        protected OAuthASResponse.OAuthTokenResponseBuilder oltuTokenBuilder;

        public TokenResponseBuilder setOltuTokenBuilder(OAuthASResponse.OAuthTokenResponseBuilder oltuTokenBuilder) {
            this.oltuTokenBuilder = oltuTokenBuilder;
            return this;
        }

        public TokenResponse build() {
            return new TokenResponse(this);
        }
    }
}
