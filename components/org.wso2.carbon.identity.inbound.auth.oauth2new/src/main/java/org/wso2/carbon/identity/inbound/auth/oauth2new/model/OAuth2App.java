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

import org.wso2.carbon.identity.application.common.model.ServiceProvider;

import java.io.Serializable;
import java.util.List;

public class OAuth2App implements Serializable {

    private static final long serialVersionUID = -2754916071514840130L;

    private ServiceProvider serviceProvider;
    private String clientId;
    private char[] clientSecret;
    private List<String> grantTypes;
    private List<String> responseTypes;
    private String redirectUri;
    private boolean isPKCEMandatory;
    private boolean isPKCEPainAllowed;

    public OAuth2App(ServiceProvider serviceProvider, String clientId) {
        this.serviceProvider = serviceProvider;
        this.clientId = clientId;
    }

    public ServiceProvider getServiceProvider() {
        return serviceProvider;
    }

    public int getAppId() {
        return serviceProvider.getApplicationID();
    }

    public String getAppName() {
        return serviceProvider.getApplicationName();
    }

    public boolean isSaasApp() {
        return serviceProvider.isSaasApp();
    }

    public boolean isUseUserstoreDomainInLocalSubjectIdentifier() {
        return serviceProvider.getLocalAndOutBoundAuthenticationConfig().isUseUserstoreDomainInLocalSubjectIdentifier();
    }

    public boolean isUseTenantDomainInLocalSubjectIdentifier() {
        return serviceProvider.getLocalAndOutBoundAuthenticationConfig().isUseTenantDomainInLocalSubjectIdentifier();
    }

    public String getClientId() {
        return clientId;
    }

    public char[] getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(char[] clientSecret) {
        this.clientSecret = clientSecret;
    }

    public List<String> getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {
        this.grantTypes = grantTypes;
    }

    public List<String> getResponseTypes() {
        return responseTypes;
    }

    public void setResponseTypes(List<String> responseTypes) {
        this.responseTypes = responseTypes;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public boolean isPKCEMandatory() {
        return isPKCEMandatory;
    }

    public void setPKCEMandatory(boolean PKCEMandatory) {
        isPKCEMandatory = PKCEMandatory;
    }

    public boolean isPKCEPainAllowed() {
        return isPKCEPainAllowed;
    }

    public void setPKCEPainAllowed(boolean PKCEPainAllowed) {
        isPKCEPainAllowed = PKCEPainAllowed;
    }
}
