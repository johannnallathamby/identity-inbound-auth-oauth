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

import org.apache.axiom.om.OMElement;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.xml.namespace.QName;

public class OAuth2ServerConfig {

    private static Log log = LogFactory.getLog(OAuth2ServerConfig.class);

    private static volatile OAuth2ServerConfig instance = new OAuth2ServerConfig();

    private OAuth2ServerConfig() {
        buildOAuth2ServerConfig();
    }

    public static OAuth2ServerConfig getInstance() {
        return instance;
    }

    private static final String CONFIG_ELEM_OAUTH = "OAuth2";

    private String oauth2AuthzEPUrl = null;
    private String oauth2TokenEPUrl = null;
    private String consentPageURL = null;
    private String errorPageURL = null;
    private long authzCodeValidity = 300;
    private long userAccessTokenValidity = 3600;
    private long applicationAccessTokenValidity = 3600;
    private long refreshTokenValidity = 24L * 3600;
    private long timeStampSkew = 300;
    private boolean isRefreshTokenRenewalEnabled = true;
    private boolean isSkipConsentPage = false;
    private int tokenPersistenceRetryCount = 5;

    private void buildOAuth2ServerConfig() {

        IdentityConfigParser configParser = IdentityConfigParser.getInstance();
        OMElement oauth2Elem = configParser.getConfigElement(CONFIG_ELEM_OAUTH);

        if (oauth2Elem == null) {
            log.warn("OAuth2 element is not available. Initializing with default values for OAuth2 configurations");
            return;
        }

        // read OAuth URLs
        parseOAuth2URLs(oauth2Elem);

        // read default timeout periods
        parseDefaultValidityPeriods(oauth2Elem);

        // read refresh token renewal config
        parseRefreshTokenRenewal(oauth2Elem);

        // read skip consent page config
        parseSkipConsentPage(oauth2Elem);

        parsePersistenceRetryCount(oauth2Elem);
    }

    public String getOAuth2AuthzEPUrl() {
        return oauth2AuthzEPUrl;
    }

    public String getOAuth2TokenEPUrl() {
        return oauth2TokenEPUrl;
    }

    public String getConsentPageURL() {
        return consentPageURL;
    }

    public String getErrorPageURL() {
        return errorPageURL;
    }

    public long getAuthzCodeValidity() {
        return authzCodeValidity;
    }

    public long getUserAccessTokenValidity() {
        return userAccessTokenValidity;
    }

    public long getApplicationAccessTokenValidity() {
        return applicationAccessTokenValidity;
    }

    public long getRefreshTokenValidity() {
        return refreshTokenValidity;
    }

    public long getTimeStampSkew() {
        return timeStampSkew;
    }

    public boolean isRefreshTokenRenewalEnabled() {
        return isRefreshTokenRenewalEnabled;
    }

    public boolean isSkipConsentPage() {
        return isSkipConsentPage;
    }

    public int getTokenPersistenceRetryCount() {
        return tokenPersistenceRetryCount;
    }

    private void parseOAuth2URLs(OMElement oauth2Elem) {

        OMElement elem = oauth2Elem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH2_AUTHZ_EP_URL));
        if(elem != null){
            if(StringUtils.isNotBlank(elem.getText())) {
                oauth2AuthzEPUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauth2Elem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH2_TOKEN_EP_URL));
        if(elem != null){
            if(StringUtils.isNotBlank(elem.getText())) {
                oauth2TokenEPUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauth2Elem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH2_CONSENT_PAGE_URL));
        if(elem != null){
            if(StringUtils.isNotBlank(elem.getText())) {
                consentPageURL = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
        elem = oauth2Elem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.OAUTH2_ERROR_PAGE_URL));
        if(elem != null){
            if(StringUtils.isNotBlank(elem.getText())) {
                errorPageURL = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
    }

    private void parseDefaultValidityPeriods(OMElement oauth2Elem) {

        OMElement authzCodeValidityElem = oauth2Elem.getFirstChildWithName(getQNameWithIdentityNS(ConfigElements
                .AUTHORIZATION_CODE_DEFAULT_VALIDITY_PERIOD));
        if (authzCodeValidityElem != null) {
            try {
                authzCodeValidity = Long.parseLong(authzCodeValidityElem.getText());
            } catch (NumberFormatException e) {
                log.error("Error occurred while parsing " + ConfigElements.AUTHORIZATION_CODE_DEFAULT_VALIDITY_PERIOD
                        + " configuration. Initializing to default value 300s.");
            }
        } else {
            if(log.isDebugEnabled()){
                log.debug(ConfigElements.AUTHORIZATION_CODE_DEFAULT_VALIDITY_PERIOD + " was not found in identity.xml" +
                        ". Initializing to default value 300s.");
            }
        }

        OMElement userAccessTokenValidity = oauth2Elem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.USER_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD));
        if (userAccessTokenValidity != null) {
            try {
                this.userAccessTokenValidity = Long.parseLong(userAccessTokenValidity.getText());
            } catch (NumberFormatException e) {
                log.error("Error occurred while parsing " + ConfigElements.USER_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD
                        + " configuration. Initializing to default value 3600s.");
            }
        } else {
            if(log.isDebugEnabled()){
                log.debug(ConfigElements.USER_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD + " was not found in identity.xml" +
                        ". Initializing to default value 3600s.");
            }
        }

        OMElement applicationAccessTokenValidity = oauth2Elem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.APPLICATION_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD));
        if (applicationAccessTokenValidity != null) {
            try {
                this.applicationAccessTokenValidity = Long.parseLong(applicationAccessTokenValidity.getText());
            } catch (NumberFormatException e) {
                log.error("Error occurred while parsing " + ConfigElements.APPLICATION_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD
                        + " configuration. Initializing to default value 3600s.");
            }
        } else {
            if(log.isDebugEnabled()){
                log.debug(ConfigElements.APPLICATION_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD + " was not found in identity.xml" +
                        ". Initializing to default value 3600s.");
            }
        }

        OMElement refreshTokenValidity = oauth2Elem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.REFRESH_TOKEN_DEFAULT_VALIDITY_PERIOD));
        if (refreshTokenValidity != null) {
            try {
                this.refreshTokenValidity = Long.parseLong(refreshTokenValidity.getText());
            } catch (NumberFormatException e) {
                log.error("Error occurred while parsing " + ConfigElements.REFRESH_TOKEN_DEFAULT_VALIDITY_PERIOD
                        + " configuration. Initializing to default value 24 x 3600s.");
            }
        } else {
            if(log.isDebugEnabled()){
                log.debug(ConfigElements.REFRESH_TOKEN_DEFAULT_VALIDITY_PERIOD + " was not found in identity.xml" +
                        ". Initializing to default value 24 x 3600s.");
            }
        }

        OMElement timeStampSkew = oauth2Elem.getFirstChildWithName(
                getQNameWithIdentityNS(ConfigElements.TIMESTAMP_SKEW));
        if (timeStampSkew != null) {
            try {
                this.timeStampSkew = Long.parseLong(timeStampSkew.getText());
            } catch (NumberFormatException e) {
                log.error("Error occurred while parsing " + ConfigElements.TIMESTAMP_SKEW + " configuration. " +
                        "Initializing to default value 0s.");
            }
        } else {
            if(log.isDebugEnabled()){
                log.debug(ConfigElements.TIMESTAMP_SKEW + " was not found in identity.xml" +
                        ". Initializing to default value 0s.");
            }
        }
    }

    private void parseRefreshTokenRenewal(OMElement oauth2Elem) {

        OMElement enableRefreshTokenRenewalElem = oauth2Elem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.RENEW_REFRESH_TOKEN_FOR_REFRESH_GRANT));
        if (enableRefreshTokenRenewalElem != null) {
            isRefreshTokenRenewalEnabled = Boolean.parseBoolean(enableRefreshTokenRenewalElem.getText());
        }
        if (log.isDebugEnabled()) {
            log.debug("RenewRefreshTokenForRefreshGrant was set to : " + isRefreshTokenRenewalEnabled);
        }
    }

    private void parseSkipConsentPage(OMElement oauth2Elem) {

        OMElement skipConsentPageElem = oauth2Elem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.SKIP_CONSENT_PAGE));
        if (skipConsentPageElem != null) {
            isSkipConsentPage = Boolean.parseBoolean(skipConsentPageElem.getText());
        }
        if (log.isDebugEnabled()) {
            log.debug("SkipConsentPage was set to : " + isSkipConsentPage);
        }
    }

    private void parsePersistenceRetryCount(OMElement oauth2Elem) {

        OMElement retryCountElem = oauth2Elem.getFirstChildWithName(getQNameWithIdentityNS(
                ConfigElements.PERSISTENCE_RETRY_COUNT));
        if (retryCountElem != null && NumberUtils.isNumber(retryCountElem.getText())) {
            tokenPersistenceRetryCount = Integer.parseInt(retryCountElem.getText());
        }
        if (log.isDebugEnabled()) {
            log.debug("TokenPersistenceRetryCount was set to : " + tokenPersistenceRetryCount);
        }
    }

    /**
     * Localpart names for the OAuth2 configurations in identity.xml.
     */
    private class ConfigElements {

        // URLs
        private static final String OAUTH2_AUTHZ_EP_URL = "OAuth2AuthzEPUrl";
        private static final String OAUTH2_TOKEN_EP_URL = "OAuth2TokenEPUrl";
        private static final String OAUTH2_CONSENT_PAGE_URL = "OAuth2ConsentPage";
        private static final String OAUTH2_ERROR_PAGE_URL = "OAuth2ErrorPage";

        // Default validity periods
        private static final String AUTHORIZATION_CODE_DEFAULT_VALIDITY_PERIOD = "AuthorizationCodeDefaultValidityPeriod";
        private static final String USER_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD = "UserAccessTokenDefaultValidityPeriod";
        private static final String APPLICATION_ACCESS_TOKEN_DEFAULT_VALIDITY_PERIOD =
                "ApplicationAccessTokenDefaultValidityPeriod";
        private static final String REFRESH_TOKEN_DEFAULT_VALIDITY_PERIOD = "RefreshTokenDefaultValidityPeriod";

        // Default timestamp skew
        private static final String TIMESTAMP_SKEW = "TimestampSkew";

        // Enable/Disable refresh token renewal on each refresh_token grant request
        private static final String RENEW_REFRESH_TOKEN_FOR_REFRESH_GRANT = "RenewRefreshTokenForRefreshGrant";

        // Skip consent page
        private static final String SKIP_CONSENT_PAGE = "SkipConsentPage";

        // Persistence retry count
        private static final String PERSISTENCE_RETRY_COUNT = "AccessTokenPersistenceRetryCount";
    }

    private QName getQNameWithIdentityNS(String localPart) {
        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, localPart);
    }
}
