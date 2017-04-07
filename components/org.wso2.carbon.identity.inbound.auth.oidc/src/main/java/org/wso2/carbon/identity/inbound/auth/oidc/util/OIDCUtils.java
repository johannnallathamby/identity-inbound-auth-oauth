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

package org.wso2.carbon.identity.inbound.auth.oidc.util;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.AuthzMessageContext;
import org.wso2.carbon.identity.inbound.auth.oidc.OIDC;
import org.wso2.carbon.identity.inbound.auth.oidc.exception.OIDCRuntimeException;
import org.wso2.carbon.identity.inbound.auth.oidc.model.OIDCServerConfig;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import javax.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.wso2.carbon.identity.inbound.auth.oidc.OIDC.IDTokenDigAlg.SHA256;
import static org.wso2.carbon.identity.inbound.auth.oidc.OIDC.IDTokenDigAlg.SHA384;
import static org.wso2.carbon.identity.inbound.auth.oidc.OIDC.IDTokenDigAlg.SHA512;

public class OIDCUtils {

    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<>();
    private static Map<Integer, Certificate> publicCerts = new ConcurrentHashMap<>();
    private static final String kid = "d0ec514a32b6f88c0abd12a2840699bdd3deba9d";

    public static String getIDTokenIssuer(String tenantDomain) {

        IdentityProvider identityProvider = null;
        try {;
            identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            throw OIDCRuntimeException.error("Error occurred while retrieving Resident IDP for tenant domain: " +
                                               tenantDomain);
        }
        FederatedAuthenticatorConfig oidcConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(
                        identityProvider.getFederatedAuthenticatorConfigs(),
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        String idTokenIssuer = IdentityApplicationManagementUtil.getPropertyValue(oidcConfig.getProperties(),
                                                                                  OIDC.IDP_ENTITY_ID);
        if(StringUtils.isBlank(idTokenIssuer)) {
            throw OIDCRuntimeException.error("Invalid OpenID Connect IdPEntityId value: " + idTokenIssuer);
        }
        return idTokenIssuer;
    }

    /**
     * Sign JWT token with RSA algorithm
     *
     * @param jwtClaimsSet contains JWT body
     * @param tenantDomain
     * @return signed JWT token
     */
    public static SignedJWT signJWTWithRSA(JWTClaimsSet jwtClaimsSet, String tenantDomain) {

        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            Key privateKey;
            if (!(privateKeys.containsKey(tenantId))) {
                // get tenant's key store manager
                KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);
                if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                    // derive key store name
                    String ksName = tenantDomain.trim().replace(".", "-");
                    String jksName = ksName + ".jks";
                    // obtain private key
                    privateKey = tenantKSM.getPrivateKey(jksName, tenantDomain);
                } else {
                    try {
                        privateKey = tenantKSM.getDefaultPrivateKey();
                    } catch (Exception e) {
                        throw OIDCRuntimeException.error("Error while obtaining private key for super tenant", e);
                    }
                }
                if(privateKey != null) {
                    privateKeys.put(tenantId, privateKey);
                } else {
                    throw OIDCRuntimeException.error("Cannot find private key for tenant domain: " + tenantDomain);
                }
            } else {
                privateKey = privateKeys.get(tenantId);
            }
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            JWSHeader.Builder builder = new JWSHeader.Builder((JWSAlgorithm) OIDCServerConfig.getInstance().getIdTokenSigAlg
                    ());
            builder.keyID(kid);
            builder.x509CertThumbprint(new Base64URL(getCertThumbPrint(tenantDomain, tenantId)));
            SignedJWT signedJWT = new SignedJWT(builder.build(), jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT;
        } catch (JOSEException e) {
            throw OIDCRuntimeException.error("Error occurred while signing JWT for tenant domain: "+ tenantDomain, e);
        }
    }

    /**
     * This method maps signature algorithm define in identity.xml to digest algorithms to generate the at_hash
     *
     */
    public static String mapSigAlgToDigAlg(Algorithm sigAlg) {

        if (JWSAlgorithm.RS256.equals(sigAlg) || JWSAlgorithm.HS256.equals(sigAlg) ||
            JWSAlgorithm.ES256.equals(sigAlg)) {
            return SHA256;
        } else if (JWSAlgorithm.RS384.equals(sigAlg) || JWSAlgorithm.HS384.equals(sigAlg) ||
                   JWSAlgorithm.ES384.equals(sigAlg)) {
            return SHA384;
        } else if (JWSAlgorithm.RS512.equals(sigAlg) || JWSAlgorithm.HS512.equals(sigAlg) ||
                   JWSAlgorithm.ES512.equals(sigAlg)) {
            return SHA512;
        }
        throw OIDCRuntimeException.error("Cannot map Signature Algorithm: " + sigAlg.getName() + " to a " +
                                           "corresponding digest algorithm");
    }

    /**
     * Helper method to get tenant's primary certificate's thumbprint.
     *
     * @param tenantDomain
     * @param tenantId
     */
    public static String getCertThumbPrint(String tenantDomain, int tenantId) {

        try {
            Certificate certificate = getTenantPrimaryCertificate(tenantDomain, tenantId);
            // TODO: maintain a hashmap with tenants' pubkey thumbprints after first initialization
            //generate the SHA-1 thumbprint of the certificate
            MessageDigest digestValue = MessageDigest.getInstance("SHA-1");
            byte[] der = certificate.getEncoded();
            digestValue.update(der);
            byte[] digestInBytes = digestValue.digest();
            String publicCertThumbprint = hexify(digestInBytes);
            String base64EncodedThumbPrint = new String(new Base64(0, null, true).encode(
                    publicCertThumbprint.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
            return base64EncodedThumbPrint;
        } catch (CertificateEncodingException e) {
            throw OIDCRuntimeException.error("Error occurred while encoding certificate for tenant domain: " +
                                               tenantDomain);
        } catch (NoSuchAlgorithmException e) {
            throw OIDCRuntimeException.error("Invalid Algorithm: SHA-1");
        }
    }

    public static Certificate getTenantPrimaryCertificate(String tenantDomain, int tenantId) {

        Certificate publicCert = null;
        if (!(publicCerts.containsKey(tenantId))) {
            try {
                IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            } catch (IdentityException e) {
                throw OIDCRuntimeException.error("Error occurred while initializing registry for tenant " +
                                                   tenantDomain, e);
            }
            // get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);
            KeyStore keyStore = null;
            try {
                if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                    // derive key store name
                    String ksName = tenantDomain.trim().replace(".", "-");
                    String jksName = ksName + ".jks";
                    keyStore = tenantKSM.getKeyStore(jksName);
                    publicCert = keyStore.getCertificate(tenantDomain);
                } else {
                    publicCert = tenantKSM.getDefaultPrimaryCertificate();
                }
            } catch (KeyStoreException e) {
                throw OIDCRuntimeException.error("Error occurred while getting primary certificate for tenant " +
                                                   "domain: "
                                                   + tenantDomain);
            } catch (Exception e) {
                throw OIDCRuntimeException.error("Error occurred while getting primary certificate for tenant " +
                                                   "domain: "
                                                   + tenantDomain);
            }
            if (publicCert != null) {
                publicCerts.put(tenantId, publicCert);
            } else {
                throw OIDCRuntimeException.error("Cannot find primary certificate for tenant domain: " +
                                                   tenantDomain);
            }
        } else {
            publicCert = publicCerts.get(tenantId);
        }
        return publicCert;
    }

    /**
     * Helper method to hexify a byte array.
     * TODO:need to verify the logic
     *
     * @param bytes
     * @return  hexadecimal representation
     */
    public static String hexify(byte bytes[]) {

        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                            +                            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        StringBuilder buf = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; ++i) {
            buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
            buf.append(hexDigits[bytes[i] & 0x0f]);
        }

        return buf.toString();
    }

    public static String calculateAtHash(Algorithm sigAlg, String accessToken) {

        String digAlg = mapSigAlgToDigAlg(sigAlg);
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(digAlg);
        } catch (NoSuchAlgorithmException e) {
            throw OIDCRuntimeException.error("Invalid Algorithm: " + digAlg);
        }
        md.update(accessToken.getBytes(StandardCharsets.UTF_8));
        byte[] digest = md.digest();
        int leftHalfBytes = 16;
        if (SHA384.equals(digAlg)) {
            leftHalfBytes = 24;
        } else if (SHA512.equals(digAlg)) {
            leftHalfBytes = 32;
        }
        byte[] leftmost = new byte[leftHalfBytes];
        for (int i = 0; i < leftHalfBytes; i++) {
            leftmost[i] = digest[i];
        }
        return new String(Base64.encodeBase64URLSafe(leftmost), StandardCharsets.UTF_8);
    }

    public static long getAuthTime(AuthzMessageContext messageContext) {

        long authTime;
        boolean isFirstLogin = false;
        Cookie commonAuthId = messageContext.getRequest().getCookieMap().get("commonAuthId");
        if(commonAuthId == null) {
            commonAuthId = ((IdentityRequest)messageContext.getParameter(OAuth2.OAUTH2_RESOURCE_OWNER_AUTHN_REQUEST))
                    .getCookieMap().get("commonAuthId");
            if(commonAuthId == null) {
                throw OIDCRuntimeException.error("Error occurred while trying to read last authenticated time of user.");
            }
            isFirstLogin = true;
        }
        String sessionContextKey = DigestUtils.sha256Hex(commonAuthId.getValue());
        SessionContext sessionContext = FrameworkUtils.getSessionContextFromCache(sessionContextKey);
        if(isFirstLogin) {
            authTime = Long.parseLong(sessionContext.getProperty(FrameworkConstants.CREATED_TIMESTAMP).toString());
        } else {
            authTime = Long.parseLong(sessionContext.getProperty(FrameworkConstants.UPDATED_TIMESTAMP).toString());
        }
        return authTime;
    }
}
