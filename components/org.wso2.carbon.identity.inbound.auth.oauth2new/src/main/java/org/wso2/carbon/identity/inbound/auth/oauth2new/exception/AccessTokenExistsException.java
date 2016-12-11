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

package org.wso2.carbon.identity.inbound.auth.oauth2new.exception;

import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;

public class AccessTokenExistsException extends OAuth2RuntimeException {

    protected AccessToken accessToken;

    protected AccessTokenExistsException(AccessToken accessToken) {
        super("ACTIVE access token already exists.");
        this.accessToken = accessToken;
    }

    protected AccessTokenExistsException(AccessToken accessToken, Throwable cause) {
        super("ACTIVE access token already exists.", cause);
        this.accessToken = accessToken;
    }

    public static AccessTokenExistsException error(AccessToken accessToken){
        return new AccessTokenExistsException(accessToken);
    }

    public static AccessTokenExistsException error(AccessToken accessToken, Throwable cause){
        return new AccessTokenExistsException(accessToken, cause);
    }

    public AccessToken getAccessToken() {
        return accessToken;
    }
}
