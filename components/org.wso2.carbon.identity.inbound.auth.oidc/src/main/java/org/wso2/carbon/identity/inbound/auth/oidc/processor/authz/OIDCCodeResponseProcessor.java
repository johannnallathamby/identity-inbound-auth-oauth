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

package org.wso2.carbon.identity.inbound.auth.oidc.processor.authz;

import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.AuthzMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz.AuthzResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz.ROApprovalResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2AuthnException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ConsentException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AuthzCode;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2ServerConfig;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.authz.CodeResponseProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Util;
import org.wso2.carbon.identity.inbound.auth.oidc.OIDC;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.request.authz.OIDCAuthzRequest;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.response.authz.OIDCAuthzResponse;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCache;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCacheCodeKey;
import org.wso2.carbon.identity.inbound.auth.oidc.cache.OIDCCacheEntry;
import org.wso2.carbon.identity.inbound.auth.oidc.handler.OIDCHandlerManager;

import java.util.List;
import java.util.Set;

/*
 * InboundRequestProcessor for response_type=code
 */
public class OIDCCodeResponseProcessor extends CodeResponseProcessor {

    private OAuthIssuerImpl oltuIssuer = new OAuthIssuerImpl(new MD5Generator());

    public boolean canHandle(IdentityRequest identityRequest) {
        if(super.canHandle(identityRequest)) {
            Set<String> scopes = OAuth2Util.buildScopeSet(identityRequest.getParameter(OAuth.OAUTH_SCOPE));
            if (scopes.contains(OIDC.OPENID_SCOPE)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public ROApprovalResponse.ROApprovalResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        AuthzMessageContext messageContext = (AuthzMessageContext)getContextIfAvailable(identityRequest);

        if(messageContext.getAuthzUser() == null) { // authentication response

            messageContext.addParameter(OAuth2.OAUTH2_RESOURCE_OWNER_AUTHN_REQUEST, identityRequest);
            AuthenticationResult authnResult = processResponseFromFrameworkLogin(messageContext, identityRequest);

            AuthenticatedUser authenticatedUser = null;
            if(authnResult.isAuthenticated()) {
                authenticatedUser = authnResult.getSubject();
                messageContext.setAuthzUser(authenticatedUser);
            } else {
                throw OAuth2AuthnException.error("Resource owner authentication failed");
            }

            boolean isConsentRequired = ((OIDCAuthzRequest)messageContext.getRequest()).isConsentRequired();
            boolean isPromptNone = ((OIDCAuthzRequest)messageContext.getRequest()).isPromptNone();

            if(isConsentRequired){
                return initiateResourceOwnerConsent(messageContext);
            } else if (!OAuth2ServerConfig.getInstance().isSkipConsentPage()) {

                String spName = messageContext.getApplication().getAppName();
                int applicationId = messageContext.getApplication().getAppId();

                if (!hasUserApprovedAppAlways(authenticatedUser, spName, applicationId)) {
                    if(!isPromptNone) {
                        return initiateResourceOwnerConsent(messageContext);
                    } else {
                        throw OAuth2ConsentException.error("Prompt contains none, but user approval required");
                    }
                } else {
                    messageContext.addParameter(OAuth2.CONSENT, "ApproveAlways");
                }
            } else {
                messageContext.addParameter(OAuth2.CONSENT, "SkipOAuth2Consent");
            }

        }

        // if this line is reached that means this is a consent response or consent is skipped due config or approve
        // always. We set the inbound request to message context only if it has gone through consent process
        // if consent consent was skipped due to configuration or approve always,
        // authenticated request and authorized request are the same
        if(!StringUtils.equals("ApproveAlways", (String)messageContext.getParameter(OAuth2.CONSENT)) &&
                !StringUtils.equals("SkipOAuth2Consent", (String)messageContext.getParameter(OAuth2.CONSENT))) {
            messageContext.addParameter(OAuth2.OAUTH2_RESOURCE_OWNER_AUTHZ_REQUEST, identityRequest);
            processConsent(messageContext);
        }

        // This cache is used for later retrieving AuthenticationResult from Token endpoint and Userinfo endpoint
        // The day we can invoke Authentication Framework via Java APIs, we can get rid of this hack
        AuthzCode authzCode = (AuthzCode) messageContext.getParameter(OAuth2.AUTHZ_CODE);
        AuthenticationResult authnResult = (AuthenticationResult) messageContext.getParameter(InboundConstants.RequestProcessor
                                                                                                      .AUTHENTICATION_RESULT);
        String nonce = ((OIDCAuthzRequest)messageContext.getRequest()).getNonce();
        List<String> acrValues = ((OIDCAuthzRequest)messageContext.getRequest()).getAcrValues();
        long authTime = (Long)authnResult.getProperty("auth_time");
        Set<OIDCAuthzRequest.Claim> claims = ((OIDCAuthzRequest) messageContext.getRequest()).getClaims();
        storeAuthnResultToCache(authzCode.getAuthzCodeId(), authzCode.getAuthzCode(), authnResult, nonce, acrValues,
                                authTime, authzCode.getScopes(), claims);

        return buildAuthzResponse(messageContext);
    }

    protected AuthzResponse.AuthzResponseBuilder buildAuthzResponse(AuthzMessageContext messageContext) {

        AuthzResponse.AuthzResponseBuilder oauth2Builder = super.buildAuthzResponse(messageContext);

        OIDCAuthzResponse.OIDCAuthzResponseBuilder oidcBuilder = new OIDCAuthzResponse.OIDCAuthzResponseBuilder
                (oauth2Builder, messageContext);

        if(messageContext.getRequest().getResponseType().contains("id_token")) {
            addIDToken(oidcBuilder, messageContext);
        }

        String responseMode = ((OIDCAuthzRequest)messageContext.getRequest()).getResponseMode();
        if(responseMode != null && OIDC.ResponseMode.FORM_POST.equals(responseMode)) {
            oidcBuilder.setResponseMode(responseMode);
        }

        AuthenticationResult authenticationResult = (AuthenticationResult)messageContext.getParameter(
                InboundConstants.RequestProcessor.AUTHENTICATION_RESULT);
        if(StringUtils.isNotBlank(authenticationResult.getAuthenticatedIdPs())){
            oauth2Builder.getBuilder().setParam(InboundConstants.LOGGED_IN_IDPS, authenticationResult.getAuthenticatedIdPs());
        }

        return oauth2Builder;
    }

    protected void addIDToken(OIDCAuthzResponse.OIDCAuthzResponseBuilder builder, AuthzMessageContext messageContext) {

        IDTokenClaimsSet idTokenClaimsSet = OIDCHandlerManager.getInstance().buildIDToken(messageContext);
        builder.setIdTokenClaimsSet(idTokenClaimsSet);
    }

    protected void storeAuthnResultToCache(String codeId, String code, AuthenticationResult authnResult, String
            nonce, List<String> acrValues, long authTime, Set<String> scopes, Set<OIDCAuthzRequest.Claim> claims) {
        OIDCCacheCodeKey key = new OIDCCacheCodeKey(codeId, code);
        OIDCCacheEntry entry = new OIDCCacheEntry(authnResult);
        entry.setNonce(nonce);
        entry.setAcrValues(acrValues);
        entry.setAuthTime(authTime);
        entry.setScopes(scopes);
        entry.setRequestedClaims(claims);
        OIDCCache.getInstance().addToCache(key, entry);
    }
}
