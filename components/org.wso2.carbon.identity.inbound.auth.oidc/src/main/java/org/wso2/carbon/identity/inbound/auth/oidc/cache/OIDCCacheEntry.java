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

package org.wso2.carbon.identity.inbound.auth.oidc.cache;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.common.cache.CacheEntry;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.request.authz.OIDCAuthzRequest;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class OIDCCacheEntry extends CacheEntry {

    private static final long serialVersionUID = 795751332737014029L;

    AuthenticationResult authnResult;
    String nonce;
    List<String> acrValues;
    long authTime = 0;
    Set<String> scopes = new HashSet();
    Set<OIDCAuthzRequest.Claim> requestedClaims = new HashSet();

    public OIDCCacheEntry(AuthenticationResult authnResult) {
        this.authnResult = authnResult;
    }

    public AuthenticationResult getAuthnResult() {
        return authnResult;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getNonce() {
        return nonce;
    }

    public void setAcrValues(List<String> acrValues) {
        this.acrValues = acrValues;
    }

    public List<String> getAcrValues() {
        return acrValues;
    }

    public void setAuthTime(long authTime) {
        this.authTime = authTime;
    }

    public long getAuthTime() {
        return authTime;
    }

    public Set<OIDCAuthzRequest.Claim> getRequestedClaims() {
        return requestedClaims;
    }

    public void setRequestedClaims(Set<OIDCAuthzRequest.Claim> requestedClaims) {
        this.requestedClaims = requestedClaims;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public void setScopes(Set<String> scopes) {
        if(scopes != null) {
            this.scopes = scopes;
        }
    }
}
