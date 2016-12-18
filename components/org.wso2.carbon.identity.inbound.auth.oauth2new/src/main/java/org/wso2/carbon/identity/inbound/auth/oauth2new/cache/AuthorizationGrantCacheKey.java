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

package org.wso2.carbon.identity.inbound.auth.oauth2new.cache;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.cache.CacheKey;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;

import java.util.HashSet;
import java.util.Set;

public class AuthorizationGrantCacheKey extends CacheKey {

    private static final long serialVersionUID = -2587261479454489617L;

    private String clientId;
    private AuthenticatedUser authzUser;
    private Set<String> scopes = new HashSet();

    public AuthorizationGrantCacheKey(String clientId, AuthenticatedUser authzUser, Set<String> scopes) {
        if(StringUtils.isBlank(clientId)) {
            throw OAuth2RuntimeException.error("Invalid client Id: " + clientId);
        } else if(authzUser == null) {
            throw OAuth2RuntimeException.error("Authorizaed user is null.");
        }
        this.clientId = clientId;
        this.authzUser = authzUser;
        if(scopes != null) {
            this.scopes = scopes;
        }
    }

    public String ClientId() {
        return clientId;
    }

    public AuthenticatedUser getAuthzUser() {
        return authzUser;
    }

    public Set<String> getScopes(){
        return scopes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuthorizationGrantCacheKey)) return false;

        AuthorizationGrantCacheKey that = (AuthorizationGrantCacheKey) o;

        if (!authzUser.equals(that.authzUser)) return false;
        if (!clientId.equals(that.clientId)) return false;
        if (!scopes.equals(that.scopes)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = clientId.hashCode();
        result = 31 * result + authzUser.hashCode();
        result = 31 * result + scopes.hashCode();
        return result;
    }
}
