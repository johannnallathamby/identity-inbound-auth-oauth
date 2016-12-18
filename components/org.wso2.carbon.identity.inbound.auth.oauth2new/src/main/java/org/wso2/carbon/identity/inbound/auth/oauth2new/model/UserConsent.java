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

package org.wso2.carbon.identity.inbound.auth.oauth2new.model;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

public class UserConsent implements Serializable {

    private static final long serialVersionUID = -4946946591400652779L;

    private AuthenticatedUser authzUser;
    private int applicationId;
    private Set<String> scopes = new HashSet();
    private boolean isTrustedAlways;

    public UserConsent(AuthenticatedUser authzUser, int applicationId, boolean isTrustedAlways) {
        this.authzUser = authzUser;
        this.applicationId = applicationId;
        this.isTrustedAlways = isTrustedAlways;
    }

    public AuthenticatedUser getAuthzUser() {
        return authzUser;
    }

    public int getApplicationId() {
        return applicationId;
    }

    public boolean isTrustedAlways() {
        return isTrustedAlways;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

}
