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
import java.sql.Timestamp;
import java.util.Set;

public class AccessToken implements Serializable {

    private static final long serialVersionUID = -7422858868711412360L;

    // This will be populated only at the persistent layer
    private String accessTokenId;

    private String accessToken;

    private String refreshToken;

    private String clientId;

    private String subjectIdentifier;

    private AuthenticatedUser authzUser;

    private Set<String> scopes;

    private String grantType;

    private String accessTokenState;

    private Timestamp accessTokenIssuedTime;

    private Timestamp refreshTokenIssuedTime;

    private long accessTokenValidity;

    private long refreshTokenValidity;

    public AccessToken(String accessToken, String clientId, String subjectIdentifier,
                       String grantType, String accessTokenState, Timestamp accessTokenIssuedTime,
                       long accessTokenValidity) {
        this.accessToken = accessToken;
        this.clientId = clientId;
        this.subjectIdentifier = subjectIdentifier;
        this.grantType = grantType;
        this.accessTokenState = accessTokenState;
        this.accessTokenIssuedTime = accessTokenIssuedTime;
        this.accessTokenValidity = accessTokenValidity;
    }

    // Clone's the access token. Needed this method because there is no method to set state on an existing access token.
    public static AccessToken createAccessToken(AccessToken accessToken, String tokenState) {

        AccessToken newAccessToken = new AccessToken(accessToken.getAccessToken(), accessToken.getClientId(),
                accessToken.getSubjectIdentifier(), accessToken.getGrantType(), tokenState,
                accessToken.getAccessTokenIssuedTime(), accessToken.getAccessTokenValidity());
        newAccessToken.setAccessTokenId(accessToken.getAccessTokenId());
        newAccessToken.setAuthzUser(accessToken.getAuthzUser());
        newAccessToken.setScopes(accessToken.getScopes());
        newAccessToken.setRefreshToken(accessToken.getRefreshToken());
        newAccessToken.setRefreshTokenIssuedTime(accessToken.getRefreshTokenIssuedTime());
        newAccessToken.setRefreshTokenValidity(accessToken.getRefreshTokenValidity());
        return accessToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getAccessTokenId() {
        return accessTokenId;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getClientId() {
        return clientId;
    }

    public String getSubjectIdentifier() {
        return subjectIdentifier;
    }

    public AuthenticatedUser getAuthzUser() {
        return authzUser;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public String getGrantType() {
        return grantType;
    }

    public String getAccessTokenState() {
        return accessTokenState;
    }

    public Timestamp getAccessTokenIssuedTime() {
        return accessTokenIssuedTime;
    }

    public Timestamp getRefreshTokenIssuedTime() {
        return refreshTokenIssuedTime;
    }

    public long getAccessTokenValidity() {
        return accessTokenValidity;
    }

    public long getRefreshTokenValidity() {
        return refreshTokenValidity;
    }

    public void setAccessTokenId(String accessTokenId) {
        this.accessTokenId = accessTokenId;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void setAuthzUser(AuthenticatedUser authzUser) {
        this.authzUser = authzUser;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    public void setRefreshTokenIssuedTime(Timestamp refreshTokenIssuedTime) {
        this.refreshTokenIssuedTime = refreshTokenIssuedTime;
    }

    public void setRefreshTokenValidity(long refreshTokenValidity) {
        this.refreshTokenValidity = refreshTokenValidity;
    }

    @Override
    public String toString() {
        return "AccessToken{" +
                "accessTokenId='" + accessTokenId + '\'' +
                ", clientId='" + clientId + '\'' +
                ", subjectIdentifier='" + subjectIdentifier + '\'' +
                ", authzUser=" + authzUser +
                ", scopes=" + scopes +
                ", grantType='" + grantType + '\'' +
                ", accessTokenState='" + accessTokenState + '\'' +
                ", accessTokenIssuedTime=" + accessTokenIssuedTime +
                ", refreshTokenIssuedTime=" + refreshTokenIssuedTime +
                ", accessTokenValidity=" + accessTokenValidity +
                ", refreshTokenValidity=" + refreshTokenValidity +
                '}';
    }
}
