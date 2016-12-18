/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.inbound.auth.oauth2ext.grant.assertion.saml2;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.OAuth;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.inbound.auth.oauth2ext.grant.assertion.saml2.internal.SAML2AssertionGrantDataHolder;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.X509CredentialImpl;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SAML2AssertionGrantHandler extends AuthorizationGrantHandler {

    private static Log log = LogFactory.getLog(SAML2AssertionGrantHandler.class);

    protected SAMLSignatureProfileValidator profileValidator = null;

    public void init(InitConfig initConfig) {
        super.init(initConfig);
        Thread thread = Thread.currentThread();
        ClassLoader loader = thread.getContextClassLoader();
        thread.setContextClassLoader(this.getClass().getClassLoader());
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw OAuth2RuntimeException.error("Error in bootstrapping the OpenSAML2 library");
        } finally {
            thread.setContextClassLoader(loader);
        }
        profileValidator = new SAMLSignatureProfileValidator();
    }


    @Override
    public boolean canHandle(MessageContext messageContext) {
        if(SAML2GrantConstants.SAML2_GRANT_TYPE.equals(
                ((TokenMessageContext) messageContext).getRequest().getGrantType())) {
            return true;
        }
        return false;
    }

    public void validateGrant(TokenMessageContext messageContext) throws OAuth2ClientException, OAuth2Exception {

        super.validateGrant(messageContext);

        SAML2AssertionGrantRequest request = (SAML2AssertionGrantRequest)messageContext.getRequest();
        Assertion assertion = request.getAssertion();
        String tenantDomain = request.getTenantDomain();

        validateIssuer(assertion, tenantDomain, messageContext);
        validateSubject(assertion, messageContext);
        validateConditions(assertion, messageContext);
        validateSubjectConfirmations(assertion, messageContext);
        validateSignature(assertion, messageContext);

        messageContext.setApprovedScopes(request.getScopes());
        messageContext.addParameter(OAuth.OAUTH_ASSERTION, assertion);
    }

    protected IdentityProvider validateIssuer(Assertion assertion, String tenantDomain,
                                              TokenMessageContext messageContext) throws SAML2BearerGrantException {

        if (assertion.getIssuer() == null || StringUtils.isBlank(assertion.getIssuer().getValue())) {
            throw SAML2BearerGrantException.error("Issuer is empty in the SAML2 assertion");
        } else {
            String issuer = assertion.getIssuer().getValue();
            try {
                IdentityProvider identityProvider = SAML2AssertionGrantDataHolder.getInstance().getIdPManager()
                        .getIdPByAuthenticatorPropertyValue(SAML2GrantConstants.IDP_ENTITY_ID,
                                                            issuer, tenantDomain, false);
                if(identityProvider == null) {
                    throw SAML2BearerGrantException.error("SAML2 Issuer : " + issuer +
                                                          " not registered as a trusted Identity Provider in tenant : " + tenantDomain);
                }
                if (IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME.equals(
                        identityProvider.getIdentityProviderName())) {
                    identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
                    FederatedAuthenticatorConfig[] fedAuthnConfigs =
                            identityProvider.getFederatedAuthenticatorConfigs();
                    FederatedAuthenticatorConfig samlAuthenticatorConfig =
                            IdentityApplicationManagementUtil.getFederatedAuthenticator(
                                    fedAuthnConfigs, IdentityApplicationConstants.Authenticator.SAML2SSO.NAME);
                    Property idPEntityIdProp = IdentityApplicationManagementUtil.getProperty(
                            samlAuthenticatorConfig.getProperties(),
                            IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID);
                    String idpEntityId = null;
                    if (idPEntityIdProp != null) {
                        idpEntityId = idPEntityIdProp.getValue();
                    }
                    if (StringUtils.isBlank(idpEntityId) || !assertion.getIssuer().getValue().equals(idpEntityId)) {
                        throw SAML2BearerGrantException.error("SAML2 Token Issuer verification failed against " +
                                                          "Resident Identity Provider in tenant : " +
                                                          tenantDomain + ". Received : " + assertion.getIssuer()
                                                                  .getValue() + ", Expected : " + idpEntityId);
                    }
                }
                messageContext.addParameter("IdentityProvider", identityProvider);
                return identityProvider;
            } catch (IdentityProviderManagementException e) {
                throw OAuth2RuntimeException.error("Error while retrieving trusted Identity Provider for SAML2 " +
                                                   "issuer: " + issuer, e);
            }
        }
    }

    // This method does not support to identify local users using SAML2 Bearer grant type because there is no
    // accurate way to identify them separate from federated users
    protected void validateSubject(Assertion assertion, TokenMessageContext messageContext) throws SAML2BearerGrantException {

        if (assertion.getSubject() != null) {
            String subjectId = assertion.getSubject().getNameID().getValue();
            if (StringUtils.isBlank(subjectId)) {
                throw SAML2BearerGrantException.error("NameID in SAML2 assertion cannot be empty.");
            }
            String idPName = ((IdentityProvider)messageContext.getParameter("IdentityProvider"))
                    .getIdentityProviderName();
            AuthenticatedUser authzUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier
                    (subjectId);
            authzUser.setFederatedIdPName(idPName);
            messageContext.setAuthzUser(authzUser);
        } else {
            throw SAML2BearerGrantException.error("Cannot find a Subject in the assertion.");
        }
    }

    protected void validateConditions(Assertion assertion, TokenMessageContext messageContext) throws
                                                                                               SAML2BearerGrantException {

        Conditions conditions = assertion.getConditions();
        if (conditions != null) {
            validateNotOnOrAfter(conditions, messageContext);
            validateAudienceRestrictions(conditions.getAudienceRestrictions(), messageContext);
        } else {
            throw SAML2BearerGrantException.error("SAML2 assertion doesn't contain Conditions.");
        }
    }

    protected void validateNotOnOrAfter(Conditions conditions, TokenMessageContext messageContext) throws
                                                                                                   SAML2BearerGrantException {

        DateTime notOnOrAfterFromConditions = null;
        if (notOnOrAfterFromConditions != null && notOnOrAfterFromConditions.compareTo(new DateTime()) < 1) {
            throw SAML2BearerGrantException.error("NotOnOrAfter is having an expired timestamp in Conditions element.");
        }
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
        messageContext.setAccessTokenValidityPeriod(conditions.getNotOnOrAfter().getMillis() - curTimeInMillis);
    }

    protected void validateAudienceRestrictions(List<AudienceRestriction> audienceRestrictions,
                                                TokenMessageContext messageContext) throws SAML2BearerGrantException {

        String tokenEndpointAlias = null;
        IdentityProvider identityProvider = (IdentityProvider) messageContext.getParameter("IdentityProvider");
        if(IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME.equals(
                identityProvider.getIdentityProviderName())) {
            FederatedAuthenticatorConfig[] fedAuthnConfigs =
                    identityProvider.getFederatedAuthenticatorConfigs();
            FederatedAuthenticatorConfig oauthAuthenticatorConfig = null;
            if(fedAuthnConfigs != null) {
                oauthAuthenticatorConfig = IdentityApplicationManagementUtil.getFederatedAuthenticator
                        (fedAuthnConfigs, IdentityApplicationConstants.Authenticator.OIDC.NAME);
                if(oauthAuthenticatorConfig != null) {
                    Property oauthProperty = IdentityApplicationManagementUtil.getProperty(
                            oauthAuthenticatorConfig.getProperties(),
                            IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL);
                    if (oauthProperty != null) {
                        tokenEndpointAlias = oauthProperty.getValue();
                    }
                }
            }
        } else {
            tokenEndpointAlias = identityProvider.getAlias();
        }
        if (StringUtils.isBlank(tokenEndpointAlias)) {
            throw SAML2BearerGrantException.error("Token endpoint alias has not been configured in the " +
                                                  "Identity Provider: " + identityProvider.getIdentityProviderName()
                                                  + " in tenant " + messageContext.getRequest().getTenantDomain());
        } else {
            messageContext.addParameter("TokenEndpointAlias", tokenEndpointAlias);
        }
        if (CollectionUtils.isNotEmpty(audienceRestrictions)) {
            boolean audienceFound = false;
            for (AudienceRestriction audienceRestriction : audienceRestrictions) {
                if (CollectionUtils.isNotEmpty(audienceRestriction.getAudiences())) {
                    for (Audience audience : audienceRestriction.getAudiences()) {
                        if (audience.getAudienceURI().equals(tokenEndpointAlias)) {
                            audienceFound = true;
                            break;
                        }
                    }
                }
                if (audienceFound) {
                    break;
                }
            }
            if (!audienceFound) {
                throw SAML2BearerGrantException.error("SAML2 assertion Audience Restriction validation failed against " +
                                                  "the audience: " + tokenEndpointAlias + " of Identity Provider " +
                                                  identityProvider.getIdentityProviderName() + " in tenant " +
                                                  messageContext.getRequest().getTenantDomain() + ".");
            }
        } else {
            throw SAML2BearerGrantException.error("SAML2 assertion doesn't contain AudienceRestrictions.");
        }
    }

    protected void validateSubjectConfirmations(Assertion assertion, TokenMessageContext messageContext) throws
                                                                                           SAML2BearerGrantException {

        DateTime notOnOrAfterFromConditions = null;
        if (assertion.getConditions() != null && assertion.getConditions().getNotOnOrAfter() != null) {
            notOnOrAfterFromConditions = assertion.getConditions().getNotOnOrAfter();
        }

        Set<DateTime> notOnOrAfterFromSubjectConfirmations = new HashSet();
        boolean bearerFound = false;
        List<String> recipientURLs = new ArrayList<>();

        List<SubjectConfirmation> subjectConfirmations = assertion.getSubject().getSubjectConfirmations();
        if (subjectConfirmations != null && !subjectConfirmations.isEmpty()) {
            for (SubjectConfirmation s : subjectConfirmations) {
                if (s.getMethod() != null) {
                    if (s.getMethod().equals(SAML2GrantConstants.SAML2_BEARER_METHOD)) {
                        bearerFound = true;
                    }
                } else {
                    throw SAML2BearerGrantException.error("Cannot find Method attribute in SubjectConfirmation " + s
                            .toString());
                }
                if (s.getSubjectConfirmationData() != null) {
                    if (s.getSubjectConfirmationData().getRecipient() != null) {
                        recipientURLs.add(s.getSubjectConfirmationData().getRecipient());
                    }
                    if (s.getSubjectConfirmationData().getNotOnOrAfter() != null) {
                        notOnOrAfterFromSubjectConfirmations.add(s.getSubjectConfirmationData().getNotOnOrAfter());
                    } else {
                        throw SAML2BearerGrantException.error("Cannot find NotOnOrAfter attribute in SubjectConfirmationData " +
                                                          s.getSubjectConfirmationData().toString());
                    }
                } else if (s.getSubjectConfirmationData() == null && notOnOrAfterFromConditions == null) {
                    throw SAML2BearerGrantException.error("Neither can find NotOnOrAfter attribute in Conditions nor SubjectConfirmationData" +
                                                      "in SubjectConfirmation " + s.toString());
                }
            }
        } else {
            SAML2BearerGrantException.error("No SubjectConfirmation exist in SAML2 assertion.");
        }

        if (!bearerFound) {
            throw SAML2BearerGrantException.error("Failed to find a SubjectConfirmation with a Method attribute having : " +
                                              SAML2GrantConstants.SAML2_BEARER_METHOD + ".");
        }
        boolean validSubjectConfirmationDataExists = false;
        if (!notOnOrAfterFromSubjectConfirmations.isEmpty()) {
            for (DateTime entry : notOnOrAfterFromSubjectConfirmations) {
                if (entry.compareTo(new DateTime()) >= 1) {
                    validSubjectConfirmationDataExists = true;
                }
            }
        }
        if (notOnOrAfterFromConditions == null && !validSubjectConfirmationDataExists) {
            throw SAML2BearerGrantException.error("No valid NotOnOrAfter element found in SubjectConfirmations.");
        }

        validateRecipients(recipientURLs, messageContext);
    }

    protected void validateRecipients(List<String> recipientURLS, TokenMessageContext messageContext) throws
                                                                                        SAML2BearerGrantException {

        IdentityProvider identityProvider = (IdentityProvider)messageContext.getParameter("IdentityProvider");
        String tokenEndpointAlias = (String)messageContext.getParameter("TokenEndpointAlias");
        String tenantDomain = messageContext.getRequest().getTenantDomain();
        if (CollectionUtils.isNotEmpty(recipientURLS) && !recipientURLS.contains(tokenEndpointAlias)) {
            throw SAML2BearerGrantException.error("None of the recipient URLs match against the token endpoint alias " +
                                              tokenEndpointAlias + " of Identity Provider " +
                                              identityProvider.getIdentityProviderName() + " in tenant " +
                                              tenantDomain + ".");
        }
    }

    protected void validateSignature(Assertion assertion, TokenMessageContext messageContext) throws
                                                                                              SAML2BearerGrantException {

        IdentityProvider identityProvider = (IdentityProvider)messageContext.getParameter("IdentityProvider");
        String tenantDomain = messageContext.getRequest().getTenantDomain();
        try {
            profileValidator.validate(assertion.getSignature());
        } catch (ValidationException e) {
            throw SAML2BearerGrantException.error("Signature does not confirm to SAML2 signature profile.", e);
        }

        X509Certificate x509Certificate = null;
        try {
            x509Certificate = (X509Certificate) IdentityApplicationManagementUtil
                    .decodeCertificate(identityProvider.getCertificate());
        } catch (CertificateException e) {
            throw SAML2BearerGrantException.error("Error occurred while decoding public certificate of " +
                                                  "Identity Provider " + identityProvider.getIdentityProviderName() +
                                                  " for tenant domain " + tenantDomain + ".");
        }

        try {
            X509Credential x509Credential = new X509CredentialImpl(x509Certificate);
            SignatureValidator signatureValidator = new SignatureValidator(x509Credential);
            signatureValidator.validate(assertion.getSignature());
            if (log.isDebugEnabled()){
                log.debug("Signature validation successful.");
            }
        } catch (ValidationException e) {
            throw SAML2BearerGrantException.error("Error while validating the signature.", e);
        }
    }

}
