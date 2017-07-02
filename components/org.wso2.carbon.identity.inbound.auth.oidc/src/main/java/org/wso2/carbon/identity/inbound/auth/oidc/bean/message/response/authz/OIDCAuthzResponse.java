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
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz.AuthzResponse;

public class OIDCAuthzResponse extends AuthzResponse {

    private static final long serialVersionUID = -8516154777518780333L;

    protected IDTokenClaimsSet idTokenClaimsSet;
    protected String responseType;
    protected String responseMode;
    protected String redirectURI;
    protected String tenantDomain;

    protected OIDCAuthzResponse(OIDCAuthzResponseBuilder builder) {
        super(builder);
        this.idTokenClaimsSet = builder.idTokenClaimsSet;
        this.responseType = builder.responseType;
        this.responseMode = builder.responseMode;
        this.redirectURI = builder.redirectURI;
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

    public String getResponseMode() {
        return responseMode;
    }

    public String getRedirectURI() {
        return redirectURI;
    }

    public static class OIDCAuthzResponseBuilder extends AuthzResponseBuilder {

        protected IDTokenClaimsSet idTokenClaimsSet;
        protected String responseType;
        protected String responseMode;
        protected String redirectURI;
        protected String tenantDomain;

        public OIDCAuthzResponseBuilder setTenantDomain(String tenantDomain) {
            this.tenantDomain = tenantDomain;
            return this;
        }

        public OIDCAuthzResponseBuilder setResponseType(String responseType) {
            this.responseType = responseType;
            return this;
        }

        public OIDCAuthzResponseBuilder setRedirectURI(String redirectURI) {
            this.redirectURI = redirectURI;
            return this;
        }
        public OIDCAuthzResponseBuilder setIdTokenClaimsSet(IDTokenClaimsSet idTokenClaimsSet) {
            this.idTokenClaimsSet = idTokenClaimsSet;
            return this;
        }

        public OIDCAuthzResponseBuilder setResponseMode(String responseMode) {
            this.responseMode = responseMode;
            return this;
        }


        public OIDCAuthzResponse build() {
            return new OIDCAuthzResponse(this);
        }
    }
}
