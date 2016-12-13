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
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.AuthzMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.authz.AuthzRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2App;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.OAuth2IdentityRequestProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Util;

import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * InboundRequestProcessor for OAuth2 Authorization Endpoint
 */
public class AuthzProcessor extends OAuth2IdentityRequestProcessor {

    //Precompile PKCE Regex pattern for performance improvement
    private static Pattern pkceCodeVerifierPattern = Pattern.compile("[\\w\\-\\._~]+");

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

        AuthzMessageContext messageContext = new AuthzMessageContext(
                (AuthzRequest) identityRequest, new HashMap<String,String>());

        validateClient(messageContext);

        return initializeResourceOwnerAuthentication(messageContext);
    }

    protected void validateClient(AuthzMessageContext messageContext) throws OAuth2ClientException {

        String clientId = messageContext.getRequest().getClientId();
        OAuth2App app = OAuth2Util.getOAuth2App(clientId, messageContext.getRequest().getTenantDomain());
        if(app == null) {
            throw OAuth2ClientException.error("Invalid clientId: " + clientId);
        }

        if(!messageContext.getRequest().getRedirectURI().equals(app.getRedirectUri())) {
            throw OAuth2ClientException.error("Invalid Redirect URI: " + app.getRedirectUri());
        }

        if(!app.getResponseTypes().contains(messageContext.getRequest().getResponseType())) {
            throw OAuth2ClientException.error("Unauthorized Response Type: " + messageContext.getRequest()
                    .getResponseType());
        }

        String pkceChallengeCode = messageContext.getRequest().getPkceCodeChallenge();
        String pkceChallengeMethod = messageContext.getRequest().getPkceCodeChallengeMethod();
        validatePkce(pkceChallengeCode, pkceChallengeMethod, app.isPKCEMandatory(), app.isPKCEPainAllowed());

        messageContext.setApplication(app);
    }

    protected FrameworkLoginResponse.FrameworkLoginResponseBuilder initializeResourceOwnerAuthentication(
            AuthzMessageContext messageContext) {

        return buildResponseForFrameworkLogin(messageContext);
    }

    protected void validatePkce(String pkceChallengeCode, String pkceChallengeMethod, boolean isPkceMandatory,
                                   boolean isPkcePlainAllowed) throws OAuth2ClientException {

        if (isPkceMandatory) {
            if (pkceChallengeCode == null || !validatePKCECodeChallenge(pkceChallengeCode, pkceChallengeMethod)) {
                throw OAuth2ClientException.error("PKCE is mandatory for this application. PKCE Challenge is not " +
                                                  "provided or is not upto RFC 7636 specification.");
            }
        }
        if (pkceChallengeCode != null && pkceChallengeMethod != null) {
            if (!OAuth2.PKCE.Challenge.PLAIN.equals(pkceChallengeMethod) &&
                !OAuth2.PKCE.Challenge.S256.equals(pkceChallengeMethod)) {
                throw OAuth2ClientException.error("Unsupported PKCE Challenge Method");
            }
        }

        if (pkceChallengeCode != null && !isPkcePlainAllowed) {
            if (pkceChallengeMethod == null || OAuth2.PKCE.Challenge.PLAIN.equals(pkceChallengeMethod)) {
                throw OAuth2ClientException.error("This application does not support \"plain\" transformation algorithm.", null);
            }
        }

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
        if(codeChallengeMethod == null || OAuth2.PKCE.Challenge.PLAIN.equals(codeChallengeMethod)) {
            return validatePKCECodeVerifier(codeChallenge);
        }
        else if (OAuth2.PKCE.Challenge.S256.equals(codeChallengeMethod)) {
            // SHA256 code challenge is 256 bits that is 256 / 6 ~= 43
            // See https://tools.ietf.org/html/rfc7636#section-3
            if(codeChallenge != null && codeChallenge.trim().length() == 43) {
                return true;
            }
        }
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
