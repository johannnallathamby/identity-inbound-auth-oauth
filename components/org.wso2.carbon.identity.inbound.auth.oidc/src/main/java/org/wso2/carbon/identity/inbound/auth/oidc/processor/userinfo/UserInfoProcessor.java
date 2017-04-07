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

package org.wso2.carbon.identity.inbound.auth.oidc.processor.userinfo;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsTransport;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.AccessTokenValidationException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2App;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.OAuth2IdentityRequestProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Utils;
import org.wso2.carbon.identity.inbound.auth.oidc.OIDC;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.context.UserInfoMessageContext;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.request.authz.OIDCAuthzRequest;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.request.userinfo.UserInfoRequest;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.response.userinfo.UserInfoResponse;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCache;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCacheAccessTokenKey;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCacheEntry;
import org.wso2.carbon.identity.inbound.auth.oidc.internal.OIDCDataHolder;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.api.RegistryService;
import org.wso2.carbon.registry.api.Resource;

import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/*
 * IdentityProcessor for OIDC Userinfo Endpoint
 */
public class UserInfoProcessor extends OAuth2IdentityRequestProcessor {

    private static final Log log = LogFactory.getLog(UserInfoResponse.class);

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        return identityRequest instanceof UserInfoRequest;
    }

    @Override
    public UserInfoResponse.UserInfoResponseBuilder process(IdentityRequest identityRequest)
            throws AccessTokenValidationException {

        UserInfoMessageContext messageContext = new UserInfoMessageContext((UserInfoRequest) identityRequest,
                                                                           new HashMap());

        AccessToken accessToken = validateAccessToken(messageContext);

        UserInfo userInfo = buildUserInfo(accessToken, messageContext);

        UserInfoResponse.UserInfoResponseBuilder userInfoResponseBuilder = new UserInfoResponse
                .UserInfoResponseBuilder(messageContext);
        userInfoResponseBuilder.setUserInfo(userInfo);
        return userInfoResponseBuilder;
    }

    protected AccessToken validateAccessToken(UserInfoMessageContext messageContext) throws AccessTokenValidationException {

        String accessTokenId = ((UserInfoRequest)messageContext.getRequest()).getAccessToken();
        AccessToken accessToken = OAuth2Utils.validateAccessToken(accessTokenId);
        messageContext.addParameter(OAuth2.ACCESS_TOKEN, accessToken);
        messageContext.setApplication(OAuth2Utils.getOAuth2App(accessToken.getClientId()));
        return accessToken;
    }

    protected UserInfo buildUserInfo(AccessToken accessToken, UserInfoMessageContext messageContext) {

        OAuth2App app = messageContext.getApplication();
        UserInfo userInfo = new UserInfo(new Subject(accessToken.getAuthzUser().getAuthenticatedSubjectIdentifier()));
        userInfo.setClaim(OIDC.USERNAME, accessToken.getAuthzUser().getUsernameAsSubjectIdentifier(
                app.isUseUserstoreDomainInLocalSubjectIdentifier(),
                app.isUseTenantDomainInLocalSubjectIdentifier()));

        OIDCCacheAccessTokenKey cacheKey = new OIDCCacheAccessTokenKey(accessToken.getAccessTokenId(),
                                                                       accessToken.getAccessToken());
        Map<String,String> retrievedClaims = new HashMap();
        OIDCCacheEntry cacheEntry = OIDCCache.getInstance().getValueFromCache(cacheKey);
        if (cacheEntry != null) {
            HashMap<ClaimMapping, String> userAttributes = (HashMap<ClaimMapping, String>) cacheEntry.getAuthnResult().getSubject()
                    .getUserAttributes();
            if (userAttributes != null) {
                String tenantDomain = messageContext.getRequest().getTenantDomain();
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                    retrievedClaims.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue());
                }
                restrictClaimsFromScopes(userInfo, cacheEntry.getScopes(), cacheEntry.getRequestedClaims(),
                                         retrievedClaims, tenantDomain, tenantId);

            }
        }
        return userInfo;
    }

    /**
     * Control claims based on the requested scopes and defined scopes in the registry
     */
    protected void restrictClaimsFromScopes(UserInfo userInfo, Set<String> scopes,
                                            Set<OIDCAuthzRequest.Claim> requestedClaims,
                                            Map<String,String> retrievedClaims, String tenantDomain, int tenantId) {

        Resource resource = null;
        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            carbonContext.setTenantId(tenantId);
            carbonContext.setTenantDomain(tenantDomain);
            RegistryService registry = OIDCDataHolder.getInstance().getRegistryService();
            resource = registry.getConfigSystemRegistry(tenantId).get(OIDC.OIDC_SCOPE_CONFIG_RESOURCE_PATH);
            if(resource == null) {
                log.error("Cannot find oidc-scope-config.xml at: " + OIDC.OIDC_SCOPE_CONFIG_RESOURCE_PATH);
                return;
            }
        } catch (RegistryException e) {
            log.error("Error while reading file oidc-scope-config.xml at: " + OIDC.OIDC_SCOPE_CONFIG_RESOURCE_PATH, e);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }

        Map<String, String> claimsforAddressScope = new HashMap<>();
        String[] arrRequestedScopeClaims = null;
        for (String requestedScope : scopes) {
            if (resource != null && resource.getProperties() != null) {
                Enumeration supportedScopes = resource.getProperties().propertyNames();
                while (supportedScopes.hasMoreElements()) {
                    String supportedScope = (String) supportedScopes.nextElement();
                    if (supportedScope.equals(requestedScope)) {
                        String requestedScopeClaims = resource.getProperty(requestedScope);
                        if (requestedScopeClaims.contains(",")) {
                            arrRequestedScopeClaims = requestedScopeClaims.split(",");
                        } else {
                            arrRequestedScopeClaims = new String[1];
                            arrRequestedScopeClaims[0] = requestedScopeClaims;
                        }
                        for (Map.Entry<String, String> entry : retrievedClaims.entrySet()) {
                            String retrievedClaim = entry.getKey();
                            if (Arrays.asList(arrRequestedScopeClaims).contains(retrievedClaim)) {
                                if (!requestedScope.equals(OIDC.ADDRESS)) {
                                    userInfo.setClaim(entry.getKey(), entry.getValue());
                                } else {
                                    claimsforAddressScope.put(entry.getKey(), entry.getValue());
                                }
                            }
                        }

                    }
                }
            }
        }
        if (claimsforAddressScope.size() > 0) {
            JSONObject jsonObject = new JSONObject();
            for (Map.Entry<String,String> entry : claimsforAddressScope.entrySet()) {
                jsonObject.put(entry.getKey(), retrievedClaims.get(entry.getKey()));
            }
            userInfo.setClaim(OIDC.ADDRESS, jsonObject);
        }
        if (retrievedClaims.containsKey(OIDC.UPDATED_AT)) {
            Object updatedAt = retrievedClaims.get(OIDC.UPDATED_AT);
            if(updatedAt != null && updatedAt instanceof String) {
                userInfo.setClaim(OIDC.UPDATED_AT, Integer.parseInt((retrievedClaims.get(OIDC.UPDATED_AT))));
            }
        }
        if (retrievedClaims.containsKey(OIDC.PHONE_NUMBER_VERIFIED)) {
            Object phoneNumberVerified = retrievedClaims.get(OIDC.PHONE_NUMBER_VERIFIED);
            if(phoneNumberVerified != null && phoneNumberVerified instanceof String) {
                userInfo.setClaim(OIDC.PHONE_NUMBER_VERIFIED, Boolean.valueOf(
                        (retrievedClaims.get(OIDC.PHONE_NUMBER_VERIFIED))));
            }
        }
        if (retrievedClaims.containsKey(OIDC.EMAIL_VERIFIED)) {
            Object emailVerified = retrievedClaims.get(OIDC.EMAIL_VERIFIED);
            if(emailVerified != null && emailVerified instanceof String) {
                userInfo.setClaim(OIDC.EMAIL_VERIFIED, Boolean.valueOf(
                        (retrievedClaims.get(OIDC.EMAIL_VERIFIED))));
            }
        }
        for(OIDCAuthzRequest.Claim requestedClaim : requestedClaims) {
            if(requestedClaim.getClaimTransport() == ClaimsTransport.USERINFO &&
               requestedClaim.getClaimRequirement() == ClaimRequirement.ESSENTIAL) {
                userInfo.setClaim(requestedClaim.getClaimURI(), retrievedClaims.get(requestedClaim.getClaimURI()));
            }
        }
    }
}
