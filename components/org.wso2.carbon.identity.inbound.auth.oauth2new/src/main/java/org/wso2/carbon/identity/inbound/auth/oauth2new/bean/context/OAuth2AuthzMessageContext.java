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

package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.authz.AuthzRequest;

import java.io.Serializable;
import java.util.Map;
import java.util.Set;

/*
 * Message context that holds information about the authorization request to the authorization endpoint
 */
public class OAuth2AuthzMessageContext<T1 extends Serializable, T2 extends Serializable> extends OAuth2MessageContext {

    private static final long serialVersionUID = 7631264521948153017L;

    private AuthenticatedUser authzUser;

    private Set<String> approvedScopes;

    private long accessTokenValidityPeriod;

    private long refreshTokenValidityPeriod;

    public OAuth2AuthzMessageContext(AuthzRequest request, Map<T1,T2> parameters) {
        super(request, parameters);
    }

    public Set<String> getApprovedScopes() {
        return approvedScopes;
    }

    public void setApprovedScopes(Set<String> approvedScopes) {
        this.approvedScopes = approvedScopes;
    }

    public long getAccessTokenValidityPeriod() {
        return accessTokenValidityPeriod;
    }

    public void setAccessTokenValidityPeriod(long accessTokenValidityPeriod) {
        this.accessTokenValidityPeriod = accessTokenValidityPeriod;
    }

    public long getRefreshTokenValidityPeriod() {
        return refreshTokenValidityPeriod;
    }

    public void setRefreshTokenValidityPeriod(long refreshTokenValidityPeriod) {
        this.refreshTokenValidityPeriod = refreshTokenValidityPeriod;
    }

    public AuthenticatedUser getAuthzUser() {
        return authzUser;
    }

    public void setAuthzUser(AuthenticatedUser authzUser) {
        this.authzUser = authzUser;
    }

    public AuthzRequest getRequest(){
        return (AuthzRequest)request;
    }

}
