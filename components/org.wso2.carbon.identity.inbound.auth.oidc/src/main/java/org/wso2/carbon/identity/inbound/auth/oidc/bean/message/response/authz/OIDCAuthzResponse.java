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

package org.wso2.carbon.identity.inbound.auth.oidc.bean.message.response.authz;

import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2AuthzMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz.AuthzResponse;

import java.util.Set;

public class OIDCAuthzResponse extends AuthzResponse {

    protected IDTokenClaimsSet idTokenClaimsSet;
    protected String responseType;
    protected String tenantDomain;

    protected OIDCAuthzResponse(OIDCAuthzResponseBuilder builder) {
        super(builder);
        this.idTokenClaimsSet = builder.idTokenClaimsSet;
        this.responseType = builder.responseType;
        this.tenantDomain = builder.tenantDomain;
    }

    public IDTokenClaimsSet getIdTokenClaimsSet() {
        return idTokenClaimsSet;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public String getResponseType() {
        return responseType;
    }

    public static class OIDCAuthzResponseBuilder extends AuthzResponseBuilder {

        protected IDTokenClaimsSet idTokenClaimsSet;
        protected String responseType;
        protected String tenantDomain;

        public OIDCAuthzResponseBuilder(AuthzResponseBuilder authzResponseBuilder,
                                        OAuth2AuthzMessageContext messageContext) {
            super(messageContext);
            this.tenantDomain = messageContext.getRequest().getTenantDomain();
            this.responseType = messageContext.getRequest().getResponseType();
            this.builder = authzResponseBuilder.getBuilder();
        }

        public void setIdTokenClaimsSet(IDTokenClaimsSet idTokenClaimsSet) {
            this.idTokenClaimsSet = idTokenClaimsSet;
        }

        public OIDCAuthzResponse build() {
            return new OIDCAuthzResponse(this);
        }
    }
}
