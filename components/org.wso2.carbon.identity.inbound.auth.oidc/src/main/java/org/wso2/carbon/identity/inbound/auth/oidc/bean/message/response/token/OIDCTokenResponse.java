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

package org.wso2.carbon.identity.inbound.auth.oidc.bean.message.response.token;

import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.token.TokenResponse;

public class OIDCTokenResponse extends TokenResponse {

    private static final long serialVersionUID = 8737357486381059687L;

    protected IDTokenClaimsSet idTokenClaimsSet;
    protected String tenantDomain;

    protected OIDCTokenResponse(OIDCTokenResponseBuilder builder) {
        super(builder);
        this.idTokenClaimsSet = builder.idTokenClaimsSet;
        this.tenantDomain = builder.tenantDomain;
    }

    public IDTokenClaimsSet getIdTokenClaimsSet() {
        return idTokenClaimsSet;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public static class OIDCTokenResponseBuilder extends TokenResponseBuilder {

        protected IDTokenClaimsSet idTokenClaimsSet;
        protected String tenantDomain;

        public OIDCTokenResponseBuilder(TokenMessageContext messageContext) {
            super(messageContext);
            this.tenantDomain = messageContext.getRequest().getTenantDomain();
        }

        public OIDCTokenResponseBuilder setIdTokenClaimsSet(IDTokenClaimsSet idTokenClaimsSet) {
            this.idTokenClaimsSet = idTokenClaimsSet;
            return this;
        }

        public OIDCTokenResponseBuilder setOLTUBuilder(OAuthASResponse.OAuthTokenResponseBuilder builder) {
            this.builder = builder;
            return this;
        }

        public OIDCTokenResponse build() {
            return new OIDCTokenResponse(this);
        }
    }
}
