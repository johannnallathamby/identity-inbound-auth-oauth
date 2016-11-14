package org.wso2.carbon.identity.inbound.auth.oidc.model;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import org.apache.axiom.om.OMElement;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.xml.namespace.QName;
import java.util.Collections;
import java.util.Iterator;
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
    private Set<String> idTokenAudiences = Collections.EMPTY_SET;


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

}
