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

package org.wso2.carbon.identity.inbound.auth.oauth2new.processor.authz;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundUtil;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.AuthzMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.authz.AuthzRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz.ConsentResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz.ROApprovalResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.jdbc.UserConsentDAO;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2AuthnException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ConsentException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2InternalException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2ServerConfig;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.UserConsent;

import java.util.Set;
import java.util.UUID;

public abstract class ROApprovalProcessor extends IdentityProcessor {

    private static final Log log = LogFactory.getLog(ROApprovalProcessor.class);

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return null;
    }

    @Override
    public String getRelyingPartyId() {
        throw new UnsupportedOperationException("Unsupported Operation getRelyingPartyId() in " + getName());
    }

    @Override
    public String getRelyingPartyId(IdentityMessageContext messageContext) {
        return messageContext.getRelyingPartyId();
    }

    @Override
    public int getPriority() {
        return 0;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {

        IdentityMessageContext context = getContextIfAvailable(identityRequest);
        if(context != null) {
            if(context.getRequest() instanceof AuthzRequest){
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

            if (!OAuth2ServerConfig.getInstance().isSkipConsentPage()) {

                String spName = messageContext.getApplication().getAppName();
                int applicationId = messageContext.getApplication().getAppId();
                Set<String> scopes = messageContext.getApprovedScopes();

                if (!hasUserApprovedAppAlways(authenticatedUser, spName, applicationId, scopes)) {
                    return initiateResourceOwnerConsent(messageContext);
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
        return buildAuthzResponse(messageContext);
    }

    /**
     * Initiate the request to obtain authorization decision from resource owner
     *
     * @param messageContext The runtime message context
     * @return OAuth2 authorization endpoint
     */
    protected ConsentResponse.ConsentResponseBuilder initiateResourceOwnerConsent(AuthzMessageContext messageContext) {

        String sessionDataKeyConsent = UUID.randomUUID().toString();
        InboundUtil.addContextToCache(sessionDataKeyConsent, messageContext);

        ConsentResponse.ConsentResponseBuilder builder = new ConsentResponse.ConsentResponseBuilder(messageContext);
        builder.setSessionDataKeyConsent(sessionDataKeyConsent);
        builder.setApplicationName(messageContext.getApplication().getAppName());
        builder.setAuthenticatedSubjectId(messageContext.getAuthzUser().getAuthenticatedSubjectIdentifier());
        builder.setParameterMap(messageContext.getRequest().getParameterMap());
        return builder;
    }

    /**
     * Process the response from resource owner approval process and establish the authorization decision
     *
     * @param messageContext The runtime message context
     * @throws OAuth2Exception Exception occurred while processing resource owner approval
     */
    protected void processConsent(AuthzMessageContext messageContext) throws OAuth2Exception {

        String consent = ((IdentityRequest)messageContext.getParameter(OAuth2.OAUTH2_RESOURCE_OWNER_AUTHZ_REQUEST))
                .getParameter(OAuth2.CONSENT);
        String spName = messageContext.getApplication().getAppName();
        int applicationId = messageContext.getApplication().getAppId();
        if (StringUtils.isNotBlank(consent)) {
            if(StringUtils.equals("ApproveAlways", consent)) {
                UserConsentDAO.getInstance().approveAppAlways(new UserConsent(messageContext.getAuthzUser(),
                                                                              applicationId, true), spName);
            } else {
                // Approve case. Do nothing.
            }
            messageContext.setApprovedScopes(messageContext.getRequest().getScopes());
        } else if(StringUtils.equals("Deny", consent)) {
            UserConsentDAO.getInstance().approveAppAlways(new UserConsent(messageContext.getAuthzUser(), applicationId,
                                                                          false), spName);
            throw OAuth2ConsentException.error("AuthenticatedUser denied the request");
        } else {
            throw OAuth2InternalException.error("Cannot find consent parameter");
        }
    }

    /**
     * Issues the authorization endpoint response
     *
     * @param messageContext The runtime message context
     * @return OAuth2 authorization endpoint response
     */
    protected abstract ROApprovalResponse.ROApprovalResponseBuilder buildAuthzResponse(AuthzMessageContext messageContext);

    protected boolean hasUserApprovedAppAlways(AuthenticatedUser authzUser, String appName, int applicationId,
                                               Set<String> scopes) {

        boolean hasApproved = false;
        try {
            UserConsent userConsent = UserConsentDAO.getInstance().getUserConsent(authzUser, applicationId, scopes);
            if(userConsent != null) {
                hasApproved = userConsent.isTrustedAlways();
            }
        } catch (OAuth2InternalException e) {
            log.error("Error occurred while checking previous consent of user: " + authzUser + " for application: " +
                      appName, e);
        }
        return hasApproved;
    }
}
