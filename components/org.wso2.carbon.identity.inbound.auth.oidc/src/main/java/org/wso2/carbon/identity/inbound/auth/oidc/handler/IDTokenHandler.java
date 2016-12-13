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

package org.wso2.carbon.identity.inbound.auth.oidc.handler;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.AuthorizedParty;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.AuthzMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2App;
import org.wso2.carbon.identity.inbound.auth.oidc.OIDC;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCache;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCacheAccessTokenKey;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCacheEntry;
import org.wso2.carbon.identity.inbound.auth.oidc.model.OIDCServerConfig;
import org.wso2.carbon.identity.inbound.auth.oidc.util.OIDCUtils;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Set;

public class IDTokenHandler extends AbstractIdentityMessageHandler {

    private static Log log = LogFactory.getLog(IDTokenHandler.class);

    // TODO: move this implementation to framework, remove it from here and update framework dependency version
    public String getName() {
        return this.getClass().getSimpleName();
    }

    public IDTokenClaimsSet buildIDToken(OAuth2MessageContext messageContext) {

        if(messageContext instanceof AuthzMessageContext) {
            return buildIDToken((AuthzMessageContext)messageContext);
        } else {
            return buildIDToken((TokenMessageContext)messageContext);
        }
    }

    protected IDTokenClaimsSet buildIDToken(AuthzMessageContext messageContext) {

        String subject = messageContext.getAuthzUser().getAuthenticatedSubjectIdentifier();
        String username = null;
        OAuth2App app = messageContext.getApplication();
        if(!messageContext.getAuthzUser().isFederatedUser()) {
            boolean useTenantDomain = app.isUseTenantDomainInLocalSubjectIdentifier();
            boolean useUserstoreDomain = app.isUseUserstoreDomainInLocalSubjectIdentifier();
            username = messageContext.getAuthzUser().getUsernameAsSubjectIdentifier(useUserstoreDomain,
                                                                                    useTenantDomain);
        } else {
            username = messageContext.getAuthzUser().getAuthenticatedSubjectIdentifier();
        }
        String tenantDomain = messageContext.getRequest().getTenantDomain();
        String clientId = messageContext.getRequest().getClientId();
        String atHash = null;
        AccessToken accessToken = (AccessToken)messageContext.getParameter(OIDC.ACCESS_TOKEN);
        if(accessToken != null) {
            if (!JWSAlgorithm.NONE.equals(OIDCServerConfig.getInstance().getIdTokenSigAlg()) &&
                !OIDC.ID_TOKEN.equalsIgnoreCase(messageContext.getRequest().getResponseType()) &&
                !OIDC.NONE.equalsIgnoreCase(messageContext.getRequest().getResponseType())) {
                atHash = OIDCUtils.calculateAtHash(OIDCServerConfig.getInstance().getIdTokenSigAlg(),
                                                   accessToken.getAccessToken());
            }
        }
        OIDCCacheEntry cacheEntry = getNonceAcrAuthTime(accessToken.getAccessTokenId(), accessToken.getAccessToken());
        String nonce = null;
        List<String> acrValues = new ArrayList();
        long authTime = 0;
        if(cacheEntry != null) {
            nonce = cacheEntry.getNonce();
            acrValues = cacheEntry.getAcrValues();
            authTime = cacheEntry.getAuthTime();
        }
        return buildIDToken(subject, username, clientId, atHash, nonce, acrValues, authTime, tenantDomain);
    }

    protected IDTokenClaimsSet buildIDToken(TokenMessageContext messageContext) {

        String subject = messageContext.getAuthzUser().getAuthenticatedSubjectIdentifier();
        String username = null;
        OAuth2App app = messageContext.getApplication();
        if(!messageContext.getAuthzUser().isFederatedUser()) {
            boolean useTenantDomain = app.isUseTenantDomainInLocalSubjectIdentifier();
            boolean useUserstoreDomain = app.isUseUserstoreDomainInLocalSubjectIdentifier();
            username = messageContext.getAuthzUser().getUsernameAsSubjectIdentifier(useUserstoreDomain,
                                                                                    useTenantDomain);
        } else {
            username = messageContext.getAuthzUser().getAuthenticatedSubjectIdentifier();
        }
        String tenantDomain = messageContext.getRequest().getTenantDomain();
        String clientId = messageContext.getApplication().getClientId();
        String atHash = null;
        AccessToken accessToken = (AccessToken)messageContext.getParameter(OIDC.ACCESS_TOKEN);;
        if (!JWSAlgorithm.NONE.equals(OIDCServerConfig.getInstance().getIdTokenSigAlg())) {
            atHash = OIDCUtils.calculateAtHash(OIDCServerConfig.getInstance().getIdTokenSigAlg(),
                                               accessToken.getAccessToken());
        }
        OIDCCacheEntry cacheEntry = getNonceAcrAuthTime(accessToken.getAccessTokenId(), accessToken
                .getAccessToken());
        String nonce = null;
        List<String> acrValues = new ArrayList();
        long authTime = 0;
        if(cacheEntry != null) {
            nonce = cacheEntry.getNonce();
            acrValues = cacheEntry.getAcrValues();
            authTime = cacheEntry.getAuthTime();
        }
        return buildIDToken(subject, username, clientId, atHash, nonce, acrValues, authTime, tenantDomain);
    }

    protected IDTokenClaimsSet buildIDToken(String subject, String username, String clientId, String atHash, String
            nonce, List<String> acrValues, long authTime, String tenantDomain) {

        String idTokenIssuer = OIDCUtils.getIDTokenIssuer(tenantDomain);
        long idTokenLifeTimeInMillis = OIDCServerConfig.getInstance().getIdTokenExpiry() * 1000;
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
        long idTokenExpiryTimeInMillis = curTimeInMillis + idTokenLifeTimeInMillis;

        Set<String> audiences = OIDCServerConfig.getInstance().getIdTokenAudiences();
        audiences.add(clientId);
        List<Audience> audienceList = new ArrayList();
        for(String aud:audiences) {
            audienceList.add(new Audience(aud));
        }

        IDTokenClaimsSet idTokenClaimSet = new IDTokenClaimsSet(new Issuer(idTokenIssuer), new Subject(subject),
                                                                audienceList, new Date(idTokenExpiryTimeInMillis),
                                                                new Date(curTimeInMillis));
        idTokenClaimSet.setAuthorizedParty(new AuthorizedParty(clientId));
        idTokenClaimSet.setClaim(OIDC.USERNAME, username);
        if (authTime != 0) {
            idTokenClaimSet.setAuthenticationTime(new Date(authTime));
        }
        if(atHash != null){
            idTokenClaimSet.setAccessTokenHash(new AccessTokenHash(atHash));
        }
        if (nonce != null) {
            idTokenClaimSet.setNonce(new Nonce(nonce));
        }
        if (acrValues != null) {
            idTokenClaimSet.setACR(new ACR("urn:mace:incommon:iap:silver"));
        }
        if (log.isDebugEnabled()) {
            log.debug(idTokenClaimSet.toJSONObject().toJSONString());
        }
        return idTokenClaimSet;
    }

    protected OIDCCacheEntry getNonceAcrAuthTime(String accessTokenId, String accessToken) {

        OIDCCacheAccessTokenKey cacheKey = new OIDCCacheAccessTokenKey(accessTokenId, accessToken);
        OIDCCacheEntry cacheEntry = OIDCCache.getInstance().getValueFromCache(cacheKey);
        return cacheEntry;
    }
}
