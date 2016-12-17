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

package org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.authzcode.AuthzCodeGrantRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AuthzCode;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2App;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2ServerConfig;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AuthzCodeGrantHandler extends AuthorizationGrantHandler {

    private static final Log log = LogFactory.getLog(AuthzCodeGrantHandler.class);

    //Precompile PKCE Regex pattern for performance improvement
    private static Pattern pkceCodeVerifierPattern = Pattern.compile("[\\w\\-\\._~]+");

    // TODO: move this implementation to framework, remove it from here and update framework dependency version
    public String getName() {
        return this.getClass().getSimpleName();
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {
        TokenMessageContext tokenMessageContext = (TokenMessageContext)messageContext;
        if(GrantType.AUTHORIZATION_CODE.toString().equals(
                ((TokenMessageContext) messageContext).getRequest().getGrantType())) {
            return true;
        }
        return false;
    }

    public void validateGrant(TokenMessageContext messageContext) throws OAuth2ClientException, OAuth2Exception {

        super.validateGrant(messageContext);

        String authorizationCode = ((AuthzCodeGrantRequest)messageContext.getRequest()).getCode();
        String redirectURI = ((AuthzCodeGrantRequest)messageContext.getRequest()).getRedirectURI();
        OAuth2DAO dao = HandlerManager.getInstance().getOAuth2DAO(messageContext);
        AuthzCode authzCode = dao.getAuthzCode(authorizationCode, messageContext);
        if (authzCode != null && !OAuth2.TokenState.INACTIVE.equals(authzCode.getCodeState())) {
            String bearerToken = dao.getAccessTokenByAuthzCode(authorizationCode, messageContext);
            dao.updateAccessTokenState(bearerToken, OAuth2.TokenState.REVOKED, messageContext);
        } else if(authzCode == null || !OAuth2.TokenState.ACTIVE.equals(authzCode.getCodeState())) {
            throw OAuth2ClientException.error("Invalid authorization code");
        }

        // Validate redirect_uri if it was presented in authorization request
        if (StringUtils.isNotBlank(authzCode.getRedirectURI())) {
            if(StringUtils.equals(authzCode.getRedirectURI(), redirectURI)) {
                throw OAuth2ClientException.error("Invalid redirect_uri");
            }
        }

        // Check whether the grant is expired
        long issuedTimeInMillis = authzCode.getIssuedTime().getTime();
        long validityPeriodInMillis = authzCode.getValidityPeriod();
        long timestampSkew = OAuth2ServerConfig.getInstance().getTimeStampSkew() * 1000;
        long currentTimeInMillis = System.currentTimeMillis();

        if ((currentTimeInMillis + timestampSkew) > (issuedTimeInMillis + validityPeriodInMillis)) {
            dao.updateAuthzCodeState(authorizationCode, OAuth2.TokenState.EXPIRED, messageContext);
            throw OAuth2ClientException.error("Authorization code expired");
        }

        OAuth2App app = messageContext.getApplication();
        String pkceCodeChallenge = authzCode.getPkceCodeChallenge();
        String pkceCodeVerifier = ((AuthzCodeGrantRequest) messageContext.getRequest()).getPKCECodeVerifier();
        String pkceChallengeMethod = authzCode.getPkceCodeChallengeMethod();

        doPKCEValidation(pkceCodeChallenge, pkceCodeVerifier, pkceChallengeMethod,
                         app.isPKCEMandatory(), app.isPKCEPainAllowed());

        messageContext.setAuthzUser(authzCode.getAuthzUser());
        messageContext.setApprovedScopes(authzCode.getScopes());
        messageContext.addParameter(OAuth2.AUTHZ_CODE, authzCode);
    }

    protected void doPKCEValidation(String referenceCodeChallenge, String codeVerifier, String challenge_method,
                                    boolean isPkceMandatory, boolean isPkcePlainAllowed) throws OAuth2ClientException {

        if (isPkceMandatory || referenceCodeChallenge != null) {

            //As per RFC 7636 Fallback to 'plain' if no code_challenge_method parameter is sent
            if(challenge_method == null || challenge_method.trim().length() == 0) {
                challenge_method = "plain";
            }

            //if app with no PKCE code verifier arrives
            if ((codeVerifier == null || codeVerifier.trim().length() == 0)) {
                //if pkce is mandatory, throw error
                if(isPkceMandatory) { // if pkce mandatory for client
                    throw OAuth2ClientException.error("No PKCE code verifier found.PKCE is mandatory for this " +
                                                      "oAuth 2.0 application.");
                } else {
                    //PKCE is optional, see if the authz code was requested with a PKCE challenge
                    if(referenceCodeChallenge == null || referenceCodeChallenge.trim().length() == 0) {
                        //since no PKCE challenge was provided
                        return;
                    } else {
                        throw OAuth2ClientException.error("Empty PKCE code_verifier sent. This authorization code " +
                                                          "requires a PKCE verification to obtain an access token.");
                    }
                }
            }
            //verify that the code verifier is upto spec as per RFC 7636
            if(!validatePKCECodeVerifier(codeVerifier)) {
                throw OAuth2ClientException.error("Code verifier used is not up to RFC 7636 specifications.");
            }
            if (OAuth2.PKCE.Challenge.PLAIN.equals(challenge_method)) {
                //if the current application explicitly doesn't support plain, throw exception
                if(!isPkcePlainAllowed) { // if pkce plain is supported
                    throw OAuth2ClientException.error("This application does not allow 'plain' transformation algorithm.");
                }
                if (!referenceCodeChallenge.equals(codeVerifier)) {
                    throw OAuth2ClientException.error("code_verifier verification failed.");
                }
            } else if (OAuth2.PKCE.Challenge.S256.equals(challenge_method)) {

                try {
                    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

                    byte[] hash = messageDigest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                    //Trim the base64 string to remove trailing CR LF characters.
                    String referencePKCECodeChallenge = new String(Base64.encodeBase64URLSafe(hash),
                                                                   StandardCharsets.UTF_8).trim();
                    if (!referencePKCECodeChallenge.equals(referenceCodeChallenge)) {
                        throw OAuth2ClientException.error("code verifier verification failed.");
                    }
                } catch (NoSuchAlgorithmException e) {
                    throw OAuth2ClientException.error("Failed to create SHA256 Message Digest.");
                }
            } else {
                //Invalid OAuth2 token response
                throw OAuth2ClientException.error("Invalid OAuth2 Token Response. Invalid PKCE Code Challenge Method: '"
                                                  + challenge_method + "'");
            }
        }
        //pkce validation successful
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
