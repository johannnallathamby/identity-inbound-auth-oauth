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

package org.wso2.carbon.identity.inbound.auth.oidc.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionHandler;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.request.authz.OIDCAuthzRequestFactory;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.response.authz.OIDCAuthzResponseFactory;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.response.token.OIDCTokenResponseFactory;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.response.userinfo.UserinfoResponseFactory;
import org.wso2.carbon.identity.inbound.auth.oidc.dao.OIDCDAO;
import org.wso2.carbon.identity.inbound.auth.oidc.handler.IDTokenHandler;
import org.wso2.carbon.identity.inbound.auth.oidc.handler.OIDCIntrospectionHandler;
import org.wso2.carbon.identity.inbound.auth.oidc.model.OIDCServerConfig;
import org.wso2.carbon.identity.inbound.auth.oidc.processor.authz.OIDCAuthzProcessor;
import org.wso2.carbon.identity.inbound.auth.oidc.processor.token.OIDCTokenProcessor;
import org.wso2.carbon.identity.inbound.auth.oidc.processor.userinfo.UserInfoProcessor;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="oidc.component" immediate="true"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 * @scr.reference name="oidc.handler.idtoken"
 * interface="org.wso2.carbon.identity.inbound.auth.oidc.handler.IDTokenHandler" cardinality="0..n"
 * policy="dynamic" bind="addIDTokenHandler" unbind="removeIDTokenHandler"
 * @scr.reference name="ApplicationManagementService"
 * interface="org.wso2.carbon.identity.application.mgt.ApplicationManagementService" cardinality="1..1"
 * policy="dynamic" bind="setApplicationManagementService" unbind="unsetApplicationManagementService"
 */
public class OIDCServiceComponent {

    private static Log log = LogFactory.getLog(OIDCServiceComponent.class);

    protected void activate(ComponentContext context) {

        try {
            OIDCDataHolder.getInstance().getIDTokenHandlers().add(new IDTokenHandler());

            ServiceRegistration oidcAuthzReqFactory = context.getBundleContext().registerService(
                    HttpIdentityRequestFactory.class.getName(), new OIDCAuthzRequestFactory(), null);
            if (oidcAuthzReqFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" OIDCAuthzRequestFactory is registered");
                }
            } else {
                log.error("OIDCAuthzRequestFactory could not be registered");
            }
            ServiceRegistration oidcAuthzRespFactory = context.getBundleContext().registerService(
                    HttpIdentityRequestFactory.class.getName(), new OIDCAuthzResponseFactory(), null);
            if (oidcAuthzRespFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" HttpOIDCAuthzResponseFactory is registered");
                }
            } else {
                log.error("HttpOIDCAuthzResponseFactory could not be registered");
            }
            ServiceRegistration oidcTokenRespFactory = context.getBundleContext().registerService(
                    HttpIdentityRequestFactory.class.getName(), new OIDCTokenResponseFactory(), null);
            if (oidcAuthzRespFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" HttpOIDCTokenResponseFactory is registered");
                }
            } else {
                log.error("HttpOIDCTokenResponseFactory could not be registered");
            }
            ServiceRegistration oidcUserInfoRespFactory = context.getBundleContext().registerService(
                    HttpIdentityRequestFactory.class.getName(), new UserinfoResponseFactory(), null);
            if (oidcUserInfoRespFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" HttpUserinfoResponseFactory is registered");
                }
            } else {
                log.error("HttpUserinfoResponseFactory could not be registered");
            }

            ServiceRegistration authzProcessor = context.getBundleContext().registerService(
                    IdentityProcessor.class.getName(), new OIDCAuthzProcessor(), null);
            if (authzProcessor != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" OIDCAuthzProcessor is registered");
                }
            } else {
                log.error("OIDCAuthzProcessor could not be registered");
            }
            ServiceRegistration tokenProcessor = context.getBundleContext().registerService(
                    IdentityProcessor.class.getName(), new OIDCTokenProcessor(), null);
            if (tokenProcessor != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" OIDCTokenProcessor is registered");
                }
            } else {
                log.error("OIDCTokenProcessor could not be registered");
            }
            ServiceRegistration userInfoProcessor = context.getBundleContext().registerService(
                    IdentityProcessor.class.getName(), new UserInfoProcessor(), null);
            if (userInfoProcessor != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" UserInfoProcessor is registered");
                }
            } else {
                log.error("UserInfoProcessor could not be registered");
            }

            ServiceRegistration scopesInitListenerReg = context.getBundleContext().registerService(
                    TenantMgtListener.class.getName(), new TenantScopesInitListener(), null);
            if (scopesInitListenerReg != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" ScopesInitListener is registered");
                }
            } else {
                log.error("ScopesInitListener could not be registered");
            }
            OIDCDAO.storeScopes(OIDCServerConfig.getInstance().getScopes(), MultitenantConstants
                    .SUPER_TENANT_DOMAIN_NAME, MultitenantConstants.SUPER_TENANT_ID);
            if (log.isDebugEnabled()) {
                log.debug("Inbound OIDC Authenticator bundle is activated");
            }
            ServiceRegistration oidcIntrospectionHandler = context.getBundleContext().registerService(
                    IntrospectionHandler.class.getName(), new OIDCIntrospectionHandler(), null);
            if (oidcIntrospectionHandler != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" OIDCIntrospectionHandler is registered");
                }
            } else {
                log.error("OIDCIntrospectionHandler could not be registered");
            }
        } catch (Throwable e) {
            log.error("Error occurred while activating Inbound OIDC Authenticator bundle");
        }
    }

    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Inbound OIDC Authenticator bundle is deactivated");
        }
    }

    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the RealmService");
        }
        OIDCDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the RealmService");
        }
        OIDCDataHolder.getInstance().setRealmService(null);
    }

    protected void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the RegistryService");
        }
        OIDCDataHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the RegistryService");
        }
        OIDCDataHolder.getInstance().setRegistryService(null);
    }

    protected void addIDTokenHandler(IDTokenHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding IDTokenHandler " + handler.getName());
        }
        OIDCDataHolder.getInstance().getIDTokenHandlers().add(handler);
    }

    protected void removeIDTokenHandler(IDTokenHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing IDTokenHandler " + handler.getName());
        }
        OIDCDataHolder.getInstance().getIDTokenHandlers().remove(handler);
    }

    protected void setApplicationManagementService(ApplicationManagementService service) {
        if (log.isDebugEnabled()) {
            log.debug("Adding ApplicationManagementService.");
        }
        OIDCDataHolder.getInstance().setAppMgtService(service);
    }

    protected void unsetApplicationManagementService(ApplicationManagementService service) {
        if (log.isDebugEnabled()) {
            log.debug("Removing ApplicationManagementService.");
        }
        OIDCDataHolder.getInstance().setAppMgtService(null);
    }
}
