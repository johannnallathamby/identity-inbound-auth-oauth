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

import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2AuthzMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.authz.AuthzRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.internal.OAuth2DataHolder;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.OAuth2IdentityRequestProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * InboundRequestProcessor for OAuth2 Authorization Endpoint
 */
public class AuthzProcessor extends OAuth2IdentityRequestProcessor {

    //Precompile PKCE Regex pattern for performance improvement
    private static Pattern pkceCodeVerifierPattern = Pattern.compile("[\\w\\-\\._~]+");

    @Override
    public String getName() {
        return "AuthzProcessor";
    }

    public int getPriority() {
        return 0;
    }

    public String getCallbackPath(IdentityMessageContext context) {
        return null;
    }

    public String getRelyingPartyId() {
        return null;
    }

    public boolean canHandle(IdentityRequest identityRequest) {
        if(identityRequest.getParameter(OAuth.OAUTH_RESPONSE_TYPE) != null) {
            return true;
        }
        return false;
    }

    public FrameworkLoginResponse.FrameworkLoginResponseBuilder process(IdentityRequest identityRequest)
            throws FrameworkException {

        OAuth2AuthzMessageContext messageContext = new OAuth2AuthzMessageContext(
                (AuthzRequest) identityRequest, new HashMap<String,String>());

        validateClient(messageContext);

        return initializeResourceOwnerAuthentication(messageContext);
    }

    protected void validateClient(OAuth2AuthzMessageContext messageContext) throws OAuth2ClientException {

        String clientId = messageContext.getRequest().getClientId();
        String redirectUri = null;
        List<String> responseTypes = new ArrayList();
        boolean isPkceMandatory = false;
        boolean isPkcePlainAllowed = false;
        ServiceProvider serviceProvider = null;
        try {
            serviceProvider = OAuth2DataHolder.getInstance().getAppMgtService()
                    .getServiceProviderByClientId(clientId, "oauth2", messageContext.getRequest().getTenantDomain());
        } catch (IdentityApplicationManagementException e) {
            throw OAuth2RuntimeException.error("Error occurred while retrieving service provider.");
        }
        if(serviceProvider == null) {
            throw OAuth2ClientException.error("Invalid Client ID: " + clientId);
        }
        // Validate clientId, redirect_uri, response_type allowed
        for(InboundAuthenticationRequestConfig config:serviceProvider.getInboundAuthenticationConfig()
                .getInboundAuthenticationRequestConfigs()) {
            if(IdentityApplicationConstants.OAuth2.NAME.equals(config.getInboundAuthType())) {
                Property[] properties = config.getProperties();
                redirectUri = IdentityApplicationManagementUtil.getPropertyValue(properties,
                                                                                  IdentityApplicationConstants.OAuth2.CALLBACK_URL);
                responseTypes = OAuth2Util.getPropertyValuesOfPropertyNameStartsWith(properties,
                                                                                                  "response_type");
                isPkceMandatory = Boolean.parseBoolean(IdentityApplicationManagementUtil.getPropertyValue(properties,
                                                                                             "pkce_mandatory"));
                isPkcePlainAllowed = Boolean.parseBoolean(IdentityApplicationManagementUtil.getPropertyValue(properties,
                                                                                       "pkce_plain_allowed"));
            }
        }

        if(!messageContext.getRequest().getRedirectURI().equals(redirectUri)) {
            throw OAuth2ClientException.error("Invalid Redirect URI: " + redirectUri);
        }

        if(!responseTypes.contains(messageContext.getRequest().getResponseType())) {
            throw OAuth2ClientException.error("Invalid Response Type: " + messageContext.getRequest()
                    .getResponseType());
        }

        String pkceChallengeCode = messageContext.getRequest().getPkceCodeChallenge();
        String pkceChallengeMethod = messageContext.getRequest().getPkceCodeChallengeMethod();
        validatePkce(pkceChallengeCode, pkceChallengeMethod, isPkceMandatory, isPkcePlainAllowed);

        messageContext.addParameter(OAuth2.OAUTH2_SERVICE_PROVIDER, serviceProvider);
    }

    protected FrameworkLoginResponse.FrameworkLoginResponseBuilder initializeResourceOwnerAuthentication(
            OAuth2AuthzMessageContext messageContext) {

        return buildResponseForFrameworkLogin(messageContext);
    }

    protected void validatePkce(String pkceChallengeCode, String pkceChallengeMethod, boolean isPkceMandatory,
                                   boolean isPkcePlainAllowed) throws OAuth2ClientException {

        // Check if PKCE is mandatory for the application
        if (isPkceMandatory) {
            if (pkceChallengeCode == null || !validatePKCECodeChallenge(pkceChallengeCode, pkceChallengeMethod)) {
                throw OAuth2ClientException.error("PKCE is mandatory for this application. PKCE Challenge is not " +
                                                  "provided or is not upto RFC 7636 specification.");
            }
        }
        //Check if the code challenge method value is neither "plain" or "s256", if so return error
        if (pkceChallengeCode != null && pkceChallengeMethod != null) {
            if (!OAuth2.PKCE_PLAIN_CHALLENGE.equals(pkceChallengeMethod) &&
                !OAuth2.PKCE_S256_CHALLENGE.equals(pkceChallengeMethod)) {
                throw OAuth2ClientException.error("Unsupported PKCE Challenge Method");
            }
        }

        // Check if "plain" transformation algorithm is disabled for the application
        if (pkceChallengeCode != null && !isPkcePlainAllowed) {
            if (pkceChallengeMethod == null || OAuth2.PKCE_PLAIN_CHALLENGE.equals(pkceChallengeMethod)) {
                throw OAuth2ClientException.error("This application does not support \"plain\" transformation algorithm.", null);
            }
        }

        // If PKCE challenge code was sent, check if the code challenge is upto specifications
        if (pkceChallengeCode != null && !validatePKCECodeChallenge(pkceChallengeCode, pkceChallengeMethod)) {
            throw OAuth2ClientException.error("Code challenge used is not up to RFC 7636 specifications.");
        }
    }

    /**
     * Verifies if the codeChallenge is upto specification as per RFC 7636
     * @param codeChallenge
     * @param codeChallengeMethod
     * @return
     */
    private boolean validatePKCECodeChallenge(String codeChallenge, String codeChallengeMethod) {
        if(codeChallengeMethod == null || OAuth2.PKCE_PLAIN_CHALLENGE.equals(codeChallengeMethod)) {
            return validatePKCECodeVerifier(codeChallenge);
        }
        else if (OAuth2.PKCE_S256_CHALLENGE.equals(codeChallengeMethod)) {
            // SHA256 code challenge is 256 bits that is 256 / 6 ~= 43
            // See https://tools.ietf.org/html/rfc7636#section-3
            if(codeChallenge != null && codeChallenge.trim().length() == 43) {
                return true;
            }
        }
        //provided code challenge method is wrong
        return false;
    }

    /**
     * Verifies if the PKCE code verifier is upto specification as per RFC 7636
     * @param codeVerifier PKCE Code Verifier sent with the token request
     * @return
     */
    private boolean validatePKCECodeVerifier(String codeVerifier) {
        Matcher pkceCodeVerifierMatcher = pkceCodeVerifierPattern.matcher(codeVerifier);
        if(!pkceCodeVerifierMatcher.matches() || (codeVerifier.length() < 43 || codeVerifier.length() > 128)) {
            return false;
        }
        return true;
    }
}
