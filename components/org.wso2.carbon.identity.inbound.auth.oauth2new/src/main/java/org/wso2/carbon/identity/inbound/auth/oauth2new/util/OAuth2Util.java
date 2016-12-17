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

package org.wso2.carbon.identity.inbound.auth.oauth2new.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.internal.OAuth2DataHolder;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2App;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2ServerConfig;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class OAuth2Util {

    public static Set<String> buildScopeSet(String scopes) {
        Set<String> scopeSet = new HashSet();
        if (StringUtils.isNotBlank(scopes)) {
            String[] scopeArray = scopes.split("\\s");
            for(String scope:scopeArray){
                if(StringUtils.isNotBlank(scope)) {
                    scopeSet.add(scope);
                }
            }
        }
        return scopeSet;
    }

    public static String buildScopeString(Set<String> scopes) {
        StringBuilder builder = new StringBuilder("");
        if(CollectionUtils.isNotEmpty(scopes)) {
            for (String scope : scopes) {
                if (StringUtils.isNotBlank(scope)) {
                    builder.append(scope);
                    builder.append(" ");
                }
            }
        }
        if (builder.length() > 0 && builder.charAt(builder.length() - 1) == ' ') {
            return builder.substring(0, builder.length() - 1);
        } else {
            return builder.toString();
        }
    }

    public static String hashScopes(Set<String> scopes){
        return hashScopes(buildScopeString(scopes));
    }

    public static String hashScopes(String scopes){
        if (scopes != null) {
            return DigestUtils.md5Hex(scopes);
        }
        throw new IllegalArgumentException("Scopes are NULL");
    }

    public static long getTokenValidityPeriod(AccessToken accessToken) {

        if (accessToken == null) {
            throw new IllegalArgumentException("AccessToken is NULL");
        }

        long remainingAccessTokenValidity = getAccessTokenValidityPeriod(accessToken);
        long remainingRefreshTokenValidity = getRefreshTokenValidityPeriod(accessToken);
        if(remainingAccessTokenValidity > 1000 && remainingRefreshTokenValidity != 0){
            return remainingAccessTokenValidity;
        } else if(remainingAccessTokenValidity < 0 && remainingRefreshTokenValidity != 0) {
            return -1;
        }
        return 0;
    }

    public static long getAccessTokenValidityPeriod(AccessToken accessToken) {

        if(accessToken == null){
            throw new IllegalArgumentException("AccessToken is NULL");
        }

        long validityPeriod = accessToken.getAccessTokenValidity();
        if (validityPeriod < 0) {
            return -1;
        }
        long timestampSkew = OAuth2ServerConfig.getInstance().getTimeStampSkew() * 1000;
        long issuedTime = accessToken.getAccessTokenIssuedTime().getTime();
        long currentTime = System.currentTimeMillis();
        long remainingValidity = issuedTime + validityPeriod - (currentTime + timestampSkew);
        if (remainingValidity > 1000) {
            return remainingValidity;
        } else {
            return 0;
        }
    }

    public static long getRefreshTokenValidityPeriod(AccessToken accessToken) {

        if (accessToken == null) {
            throw new IllegalArgumentException("AccessToken is NULL");
        }

        long validityPeriod = accessToken.getRefreshTokenValidity();
        if (validityPeriod < 0) {
            return -1;
        }
        long skew = OAuth2ServerConfig.getInstance().getTimeStampSkew();
        long refreshTokenValidity = accessToken.getRefreshTokenValidity();
        long currentTime = System.currentTimeMillis();
        long refreshTokenIssuedTime = accessToken.getRefreshTokenIssuedTime().getTime();
        long remainingRefreshTokenValidity = (refreshTokenIssuedTime + refreshTokenValidity)
                - (currentTime + skew);
        if(remainingRefreshTokenValidity > 1000){
            return remainingRefreshTokenValidity;
        }
        return 0;
    }

    public static String createUniqueAuthzGrantString(AccessToken accessToken) {
        return createUniqueAuthzGrantString(accessToken.getAuthzUser(), accessToken.getClientId(), accessToken
                .getScopes());
    }

    public static String createUniqueAuthzGrantString(AuthenticatedUser authzUser, String clientId,
                                                      Set<String> scopes) {
        if(authzUser == null || StringUtils.isBlank(clientId)){
            throw new IllegalArgumentException("Invalid arguments: AuthenticatedUser is " + authzUser + " and " +
                    "clientId is " + clientId);
        }
        StringBuilder builder = new StringBuilder("");
        builder.append(authzUser.toString()).append(":").append(clientId);
        if(!scopes.isEmpty()){
            builder.append(":").append(OAuth2Util.buildScopeString(scopes));
        }
        return builder.toString();
    }

    public static List<String> getPropertyValuesOfPropertyNameStartsWith(Property[] properties, String propNameStartsWith) {
        List<String> propValueSet = new ArrayList<String>();
        for (Property prop : properties) {
            if (prop.getName().startsWith(propNameStartsWith)) {
                propValueSet.add(prop.getValue());
            }
        }
        return propValueSet;
    }

    public static OAuth2App getOAuth2App(ServiceProvider serviceProvider) {

        if(serviceProvider == null) {
            throw new IllegalArgumentException("ServiceProvider is null.");
        }
        for (InboundAuthenticationRequestConfig config : serviceProvider.getInboundAuthenticationConfig()
                .getInboundAuthenticationRequestConfigs()) {
            if ("test".equals(config.getInboundAuthType())) {
                Property[] properties = config.getProperties();
                String clientId = IdentityApplicationManagementUtil.getPropertyValue(
                        properties, IdentityApplicationConstants.OAuth2.CLIENT_ID);
                char[] clientSecret = IdentityApplicationManagementUtil.getPropertyValue(
                        properties, IdentityApplicationConstants.OAuth2.CLIENT_SECRET).toCharArray();
                String redirectUri = IdentityApplicationManagementUtil.getPropertyValue(
                        properties, IdentityApplicationConstants.OAuth2.CALLBACK_URL);
                List<String> responseTypes = OAuth2Util.getPropertyValuesOfPropertyNameStartsWith(
                        properties, "supported_response_type");
                List<String> grantTypes = OAuth2Util.getPropertyValuesOfPropertyNameStartsWith(
                        properties, "supported_grant_type");
                boolean isPkceMandatory = Boolean.parseBoolean(IdentityApplicationManagementUtil.getPropertyValue
                        (properties, "pkce_mandatory"));
                boolean isPkcePlainAllowed = Boolean.parseBoolean(IdentityApplicationManagementUtil.getPropertyValue
                        (properties, "pkce_plain_allowed"));
                OAuth2App app = new OAuth2App(serviceProvider, clientId);
                app.setClientSecret(clientSecret);
                app.setResponseTypes(responseTypes);
                app.setGrantTypes(grantTypes);
                app.setRedirectUri(redirectUri);
                app.setPKCEMandatory(isPkceMandatory);
                app.setPKCEPainAllowed(isPkcePlainAllowed);
                return app;
            }
        }
        return null;
    }

    public static OAuth2App getOAuth2App(String clientId, String tenantDomain) {

        ServiceProvider serviceProvider = null;
        try {
            serviceProvider = OAuth2DataHolder.getInstance().getAppMgtService()
                    .getServiceProviderByClientId(clientId, "test", tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw OAuth2RuntimeException.error("Error occurred while retrieving service provider.");
        }
        if(serviceProvider != null) {
            return getOAuth2App(serviceProvider);
        }
        return null;
    }

    public static AuthenticatedUser createLocalAuthenticatedUser(User user, TokenMessageContext messageContext) {

        AuthenticatedUser authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(
                user.toString());
        boolean useTenantDomain = messageContext.getApplication().isUseUserstoreDomainInLocalSubjectIdentifier();
        boolean useUserStoreDomain = messageContext.getApplication().isUseTenantDomainInLocalSubjectIdentifier();
        String subjectId = authenticatedUser.getUsernameAsSubjectIdentifier(useUserStoreDomain, useTenantDomain);
        authenticatedUser.setAuthenticatedSubjectIdentifier(subjectId);
        return authenticatedUser;
    }

    public static AuthenticatedUser createLocalAuthenticatedUser(String username, String userStoreDomain, String
            tenantDomain, TokenMessageContext messageContext) {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(username);
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        authenticatedUser.setTenantDomain(tenantDomain);
        boolean useTenantDomain = messageContext.getApplication().isUseUserstoreDomainInLocalSubjectIdentifier();
        boolean useUserStoreDomain = messageContext.getApplication().isUseTenantDomainInLocalSubjectIdentifier();
        String subjectId = authenticatedUser.getUsernameAsSubjectIdentifier(useUserStoreDomain, useTenantDomain);
        authenticatedUser.setAuthenticatedSubjectIdentifier(subjectId);
        return authenticatedUser;
    }
}
