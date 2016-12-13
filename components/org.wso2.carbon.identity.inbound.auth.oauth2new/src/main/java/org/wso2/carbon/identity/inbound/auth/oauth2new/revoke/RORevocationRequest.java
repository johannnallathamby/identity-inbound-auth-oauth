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

package org.wso2.carbon.identity.inbound.auth.oauth2new.revoke;

import edu.emory.mathcs.backport.java.util.Collections;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.OAuth2IdentityRequest;

import java.util.HashSet;
import java.util.Set;

public class RORevocationRequest extends OAuth2IdentityRequest {

    private static final long serialVersionUID = -6509841728198979078L;

    protected AuthenticatedUser user;
    protected Set<String> clientIds = new HashSet();
    protected Set<String> scopes = new HashSet();

    public RORevocationRequest(RORevokeRequestBuilder builder) {
        super(builder);
        this.user = builder.user;
        this.clientIds = builder.clientIds;
        this.scopes = builder.scopes;
    }

    public AuthenticatedUser getUser() {
        return user;
    }

    public Set<String> getClientIds() {
        return Collections.unmodifiableSet(clientIds);
    }

    public Set<String> getScopes() {
        return Collections.unmodifiableSet(scopes);
    }

    public static class RORevokeRequestBuilder extends OAuth2IdentityRequest.OAuth2IdentityRequestBuilder {

        protected AuthenticatedUser user;
        protected Set<String> clientIds = new HashSet();
        protected Set<String> scopes = new HashSet();

        public RORevokeRequestBuilder(AuthenticatedUser user) {
            this.user = user;
        }

        public RORevokeRequestBuilder setClientIds(Set<String> clientIds) {
            if(CollectionUtils.isNotEmpty(clientIds)) {
                this.clientIds = clientIds;
            }
            return this;
        }

        public RORevokeRequestBuilder addClientId(String clientId) {
            if(StringUtils.isNotBlank(clientId)) {
                this.clientIds.add(clientId);
            }
            return this;
        }

        public RORevokeRequestBuilder addClientIds(Set<String> clientIds) {
            for(String clientId:clientIds) {
                addClientId(clientId);
            }
            return this;
        }

        public RORevokeRequestBuilder setScopes(Set<String> scopes) {
            if(CollectionUtils.isNotEmpty(scopes)) {
                this.scopes = scopes;
            }
            return this;
        }

        public RORevokeRequestBuilder addScope(String scope) {
            if(StringUtils.isNotBlank(scope)) {
                this.scopes.add(scope);
            }
            return this;
        }

        public RORevokeRequestBuilder addScopes(Set<String> scopes) {
            for(String scope:scopes) {
                addScope(scope);
            }
            return this;
        }

        @Override
        public RORevocationRequest build() {
            return new RORevocationRequest(this);
        }
    }
}
