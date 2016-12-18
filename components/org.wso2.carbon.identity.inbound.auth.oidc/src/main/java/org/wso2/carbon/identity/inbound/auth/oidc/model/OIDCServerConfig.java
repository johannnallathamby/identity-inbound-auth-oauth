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

package org.wso2.carbon.identity.inbound.auth.oidc.model;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.inbound.auth.oidc.OIDC;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

public class OIDCServerConfig {

    private static Log log = LogFactory.getLog(OIDCServerConfig.class);

    private static volatile OIDCServerConfig instance = new OIDCServerConfig();

    private static final String CONFIG_ELEM_OIDC = "OIDC";

    private static final String OIDC_USERINFO_EP_URL = "OIDCUserInfoEPUrl";

    private static final String ID_TOKEN = "IDToken";
    private static final String ID_TOKEN_ISSUER = "Issuer";
    private static final String ID_TOKEN_EXP = "Expiry";
    private static final String ID_TOKEN_SIG_ALG = "SigAlg";
    private static final String AUDIENCES = "Audiences";
    private static final String AUDIENCE = "Audience";

    private String userInfoUrl = null;

    private String idTokenIssuer = null;
    private int idTokenExpiry = 300;
    private Algorithm idTokenSigAlg = JWSAlgorithm.RS256;
    private Set<String> idTokenAudiences = new HashSet();

    private Map<String,String> scopes = new HashMap();


    private OIDCServerConfig() {
        buildOIDCServerConfig();
    }

    public static OIDCServerConfig getInstance() {
        return instance;
    }

    private void buildOIDCServerConfig() {

        IdentityConfigParser configParser = IdentityConfigParser.getInstance();
        OMElement oidcElem = configParser.getConfigElement(CONFIG_ELEM_OIDC);

        if (oidcElem == null) {
            log.warn("OIDC element is not available. Initializing with default values for OIDC configurations");
            return;
        }

        // read OAuth URLs
        parseOIDCURLs(oidcElem);

        // read default timeout periods
        parseIDTokenConfig(oidcElem);

    }

    private void parseOIDCURLs(OMElement oidcElem) {
        OMElement elem = oidcElem.getFirstChildWithName(getQNameWithIdentityNS(OIDC_USERINFO_EP_URL));
        if(elem != null){
            if(StringUtils.isNotBlank(elem.getText())) {
                userInfoUrl = IdentityUtil.fillURLPlaceholders(elem.getText());
            }
        }
    }

    private void parseIDTokenConfig(OMElement oidcElem) {
        OMElement elem = oidcElem.getFirstChildWithName(getQNameWithIdentityNS(ID_TOKEN));
        if(elem != null){
            OMElement issuerElem = elem.getFirstChildWithName(getQNameWithIdentityNS(ID_TOKEN_ISSUER));
            if(issuerElem != null) {
                if(StringUtils.isNotBlank(issuerElem.getText())) {
                    idTokenIssuer = IdentityUtil.fillURLPlaceholders(issuerElem.getText());
                }
            }
            OMElement idTokenExpElem = elem.getFirstChildWithName(getQNameWithIdentityNS(ID_TOKEN_ISSUER));
            if(idTokenExpElem != null) {
                if(StringUtils.isNotBlank(idTokenExpElem.getText()) && NumberUtils.isNumber(idTokenExpElem.getText())) {
                    idTokenExpiry = Integer.parseInt(idTokenExpElem.getText());
                }
            }
            OMElement idTokenSigAlgElem = elem.getFirstChildWithName(getQNameWithIdentityNS(ID_TOKEN_ISSUER));
            if(idTokenSigAlgElem != null) {
                if(StringUtils.isNotBlank(idTokenSigAlgElem.getText())) {
                    idTokenSigAlg = JWSAlgorithm.parse(idTokenSigAlgElem.getText());
                    if(idTokenSigAlg == null) {
                        idTokenSigAlg = JWSAlgorithm.RS256;
                    }
                }
            }
            OMElement audiencesElem = elem.getFirstChildWithName(getQNameWithIdentityNS(AUDIENCES));
            if(audiencesElem != null) {
                Iterator<OMElement> elems = audiencesElem.getChildrenWithName(getQNameWithIdentityNS(AUDIENCE));
                while(elems.hasNext()) {
                    OMElement audienceElem = elems.next();
                    if(StringUtils.isNotBlank(audienceElem.getText())) {
                        idTokenAudiences.add(IdentityUtil.fillURLPlaceholders(issuerElem.getText()));
                    }
                }
            }
        }
    }

    private void buildScopeConfig() {

        String identityConfPath = IdentityUtil.getIdentityConfigDirPath();
        String confXml =
                Paths.get(identityConfPath, OIDC.OIDC_SCOPE_CONFIG_FILE_NAME).toString();
        File configfile = new File(confXml);
        if (!configfile.exists()) {
            log.warn(OIDC.OIDC_SCOPE_CONFIG_FILE_NAME + " is cannot be found in " + identityConfPath + ". " +
                     "Initializing with defaults");
        }

        XMLStreamReader parser = null;
        InputStream stream = null;
        try {
            stream = new FileInputStream(configfile);
            parser = XMLInputFactory.newInstance()
                    .createXMLStreamReader(stream);
            StAXOMBuilder builder = new StAXOMBuilder(parser);
            OMElement documentElement = builder.getDocumentElement();
            Iterator iterator = documentElement.getChildElements();
            while (iterator.hasNext()) {
                OMElement omElement = (OMElement) iterator.next();
                String configType = omElement.getAttributeValue(new QName(
                        "id"));
                scopes.put(configType, loadClaimConfig(omElement));
            }
        } catch (XMLStreamException e) {
            log.warn("Error while creating XMLStreamReader from " + OIDC.OIDC_SCOPE_CONFIG_FILE_NAME, e);
        } catch (FileNotFoundException e) {
            log.warn("Error while loading " + OIDC.OIDC_SCOPE_CONFIG_FILE_NAME, e);
        } finally {
            try {
                if (parser != null) {
                    parser.close();
                }
            } catch (XMLStreamException e) {
                log.error("Error while closing XMLStreamReader for " + OIDC.OIDC_SCOPE_CONFIG_FILE_NAME, e);
            }
            if (stream != null) {
                IdentityIOStreamUtils.closeInputStream(stream);
            }
        }
    }

    private static String loadClaimConfig(OMElement configElement) {
        StringBuilder claimConfig = new StringBuilder();
        Iterator it = configElement.getChildElements();
        while (it.hasNext()) {
            OMElement element = (OMElement) it.next();
            if ("Claim".equals(element.getLocalName())) {
                claimConfig.append(element.getText());
            }
        }
        return claimConfig.toString();
    }

    private QName getQNameWithIdentityNS(String localPart) {
        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, localPart);
    }

    public String getUserInfoUrl() {
        return userInfoUrl;
    }

    public String getIdTokenIssuer() {
        return idTokenIssuer;
    }

    public int getIdTokenExpiry() {
        return idTokenExpiry;
    }

    public Algorithm getIdTokenSigAlg() {
        return idTokenSigAlg;
    }

    public Set<String> getIdTokenAudiences() {
        return idTokenAudiences;
    }

    public Map<String,String> getScopes() {
        return scopes;
    }

}
