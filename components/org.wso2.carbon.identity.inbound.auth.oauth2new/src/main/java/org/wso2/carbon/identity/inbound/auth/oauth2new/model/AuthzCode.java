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

public class AuthzCode implements Serializable {

    private static final long serialVersionUID = -3686811436791874738L;

    // This will be populated only at the persistent layer
    private String authzCodeId;

    private String authzCode;

    private String clientId;

    private String redirectURI;

    private AuthenticatedUser authzUser;

    private String subjectIdentifier;

    private Set<String> scopes;

    private Timestamp issuedTime;

    private long validityPeriod;

    private String codeState;

    // This will be populated only at the persistent layer
    private String accessTokenId;

    private String pkceCodeChallenge;

    private String pkceCodeChallengeMethod;

    public AuthzCode(String authzCode, String clientId, String redirectURI, String subjectIdentifier,
                     Timestamp issuedTime, long validityPeriod, String codeState) {

        this.authzCode = authzCode;
        this.clientId = clientId;
        this.redirectURI = redirectURI;
        this.subjectIdentifier = subjectIdentifier;
        this.issuedTime = issuedTime;
        this.validityPeriod = validityPeriod;
        this.codeState = codeState;
    }

    public static AuthzCode createAuthzCode(AuthzCode authzCode, String codeState) {
        AuthzCode newAuthzCode = new AuthzCode(authzCode.getAuthzCode(), authzCode.getClientId(),
                authzCode.getRedirectURI(), authzCode.getSubjectIdentifer(), authzCode.getIssuedTime(),
                authzCode.getValidityPeriod(), codeState);
        newAuthzCode.setAuthzCodeId(authzCode.getAuthzCodeId());
        newAuthzCode.setScopes(authzCode.getScopes());
        newAuthzCode.setPkceCodeChallenge(authzCode.getPkceCodeChallenge());
        newAuthzCode.setPkceCodeChallengeMethod(authzCode.getPkceCodeChallengeMethod());
        return newAuthzCode;
    }

    public String getAuthzCodeId() {
        return authzCodeId;
    }

    public String getAuthzCode() {
        return authzCode;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectURI() {
        return redirectURI;
    }

    public String getSubjectIdentifer() {
        return subjectIdentifier;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public Timestamp getIssuedTime() {
        return issuedTime;
    }

    public long getValidityPeriod() {
        return validityPeriod;
    }

    public String getCodeState() {
        return codeState;
    }

    public String getAccessTokenId() {
        return accessTokenId;
    }

    public void setAuthzCodeId(String authzCodeId) {
        this.authzCodeId = authzCodeId;
    }

    public void setAuthzUser(AuthenticatedUser authzUser) {
        this.authzUser = authzUser;
    }

    public AuthenticatedUser getAuthzUser() {
        return authzUser;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    public void setAccessTokenId(String accessTokenId) {
        this.accessTokenId = accessTokenId;
    }

    public String getPkceCodeChallenge() {
        return pkceCodeChallenge;
    }

    public void setPkceCodeChallenge(String pkceCodeChallenge) {
        this.pkceCodeChallenge = pkceCodeChallenge;
    }

    public String getPkceCodeChallengeMethod() {
        return pkceCodeChallengeMethod;
    }

    public void setPkceCodeChallengeMethod(String pkceCodeChallengeMethod) {
        this.pkceCodeChallengeMethod = pkceCodeChallengeMethod;
    }

    @Override
    public String toString() {
        return "AuthzCode{" +
               "authzCodeId='" + authzCodeId + '\'' +
               ", clientId='" + clientId + '\'' +
               ", redirectURI='" + redirectURI + '\'' +
               ", authzUser=" + authzUser +
               ", subjectIdentifer=" + subjectIdentifier +
               ", scopes=" + scopes +
               ", issuedTime=" + issuedTime +
               ", validityPeriod=" + validityPeriod +
               ", codeState='" + codeState + '\'' +
               ", accessTokenId='" + accessTokenId + '\'' +
               ", pkceCodeChallengeMethod='" + pkceCodeChallengeMethod + '\'' +
               '}';
    }
}
