/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oidc.dcr.model;

import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequestProfile;


public class OIDCRegistrationRequestProfile extends RegistrationRequestProfile {

    public String sectorIdentifierUri;
    public String subjectType;
    public String idTokenSignedResponseAlg;
    public String idTokenEncryptedResponseAlg;
    public String idTokenEncryptedResponseEnc;
    public String userinfoSignedResponseAlg;
    public String userinfoencryptedResponseAlg;
    public String userinfoEncryptedResponseEnc;
    public String requestObjectSigningAlg;
    public String requestObjectEncryptionAlg;
    public String requestObjectEncryptionEnc;
    public String tokenEndpointAuthSigningAlg;
    public String defaultMaxAge;
    public String requireAuthTime;
    public String defaultAcrValues;
    public String initiateLoginUri;
    public String requestUris;

    public String getSectorIdentifierUri() {
        return sectorIdentifierUri;
    }

    public void setSectorIdentifierUri(String sectorIdentifierUri) {
        this.sectorIdentifierUri = sectorIdentifierUri;
    }

    public String getSubjectType() {
        return subjectType;
    }

    public void setSubjectType(String subjectType) {
        this.subjectType = subjectType;
    }

    public String getIdTokenSignedResponseAlg() {
        return idTokenSignedResponseAlg;
    }

    public void setIdTokenSignedResponseAlg(String idTokenSignedResponseAlg) {
        this.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
    }

    public String getIdTokenEncryptedResponseAlg() {
        return idTokenEncryptedResponseAlg;
    }

    public void setIdTokenEncryptedResponseAlg(String idTokenEncryptedResponseAlg) {
        this.idTokenEncryptedResponseAlg = idTokenEncryptedResponseAlg;
    }

    public String getIdTokenEncryptedResponseEnc() {
        return idTokenEncryptedResponseEnc;
    }

    public void setIdTokenEncryptedResponseEnc(String idTokenEncryptedResponseEnc) {
        this.idTokenEncryptedResponseEnc = idTokenEncryptedResponseEnc;
    }

    public String getUserinfoSignedResponseAlg() {
        return userinfoSignedResponseAlg;
    }

    public void setUserinfoSignedResponseAlg(String userinfoSignedResponseAlg) {
        this.userinfoSignedResponseAlg = userinfoSignedResponseAlg;
    }

    public String getUserinfoencryptedResponseAlg() {
        return userinfoencryptedResponseAlg;
    }

    public void setUserinfoencryptedResponseAlg(String userinfoencryptedResponseAlg) {
        this.userinfoencryptedResponseAlg = userinfoencryptedResponseAlg;
    }

    public String getUserinfoEncryptedResponseEnc() {
        return userinfoEncryptedResponseEnc;
    }

    public void setUserinfoEncryptedResponseEnc(String userinfoEncryptedResponseEnc) {
        this.userinfoEncryptedResponseEnc = userinfoEncryptedResponseEnc;
    }

    public String getRequestObjectSigningAlg() {
        return requestObjectSigningAlg;
    }

    public void setRequestObjectSigningAlg(String requestObjectSigningAlg) {
        this.requestObjectSigningAlg = requestObjectSigningAlg;
    }

    public String getRequestObjectEncryptionAlg() {
        return requestObjectEncryptionAlg;
    }

    public void setRequestObjectEncryptionAlg(String requestObjectEncryptionAlg) {
        this.requestObjectEncryptionAlg = requestObjectEncryptionAlg;
    }

    public String getRequestObjectEncryptionEnc() {
        return requestObjectEncryptionEnc;
    }

    public void setRequestObjectEncryptionEnc(String requestObjectEncryptionEnc) {
        this.requestObjectEncryptionEnc = requestObjectEncryptionEnc;
    }

    public String getTokenEndpointAuthSigningAlg() {
        return tokenEndpointAuthSigningAlg;
    }

    public void setTokenEndpointAuthSigningAlg(String tokenEndpointAuthSigningAlg) {
        this.tokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg;
    }

    public String getDefaultMaxAge() {
        return defaultMaxAge;
    }

    public void setDefaultMaxAge(String defaultMaxAge) {
        this.defaultMaxAge = defaultMaxAge;
    }

    public String getRequireAuthTime() {
        return requireAuthTime;
    }

    public void setRequireAuthTime(String requireAuthTime) {
        this.requireAuthTime = requireAuthTime;
    }

    public String getDefaultAcrValues() {
        return defaultAcrValues;
    }

    public void setDefaultAcrValues(String defaultAcrValues) {
        this.defaultAcrValues = defaultAcrValues;
    }

    public String getInitiateLoginUri() {
        return initiateLoginUri;
    }

    public void setInitiateLoginUri(String initiateLoginUri) {
        this.initiateLoginUri = initiateLoginUri;
    }

    public String getRequestUris() {
        return requestUris;
    }

    public void setRequestUris(String requestUris) {
        this.requestUris = requestUris;
    }
}
