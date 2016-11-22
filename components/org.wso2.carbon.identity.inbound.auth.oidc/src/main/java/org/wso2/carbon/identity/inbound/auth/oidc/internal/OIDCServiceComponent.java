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

package org.wso2.carbon.identity.inbound.auth.oidc.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.inbound.auth.oidc.dao.OIDCDAO;
import org.wso2.carbon.identity.inbound.auth.oidc.handler.IDTokenHandler;
import org.wso2.carbon.identity.inbound.auth.oidc.model.OIDCServerConfig;
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
 */
public class OIDCServiceComponent {

    private static Log log = LogFactory.getLog(OIDCServiceComponent.class);

    protected void activate(ComponentContext context) {

        try {
            ServiceRegistration scopesInitListenerReg = context.getBundleContext().registerService(
                    TenantMgtListener.class.getName(), new ScopesInitListener(), null);
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
        OIDCServiceComponentHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the RealmService");
        }
        OIDCServiceComponentHolder.getInstance().setRealmService(null);
    }

    protected void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the RegistryService");
        }
        OIDCServiceComponentHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the RegistryService");
        }
        OIDCServiceComponentHolder.getInstance().setRegistryService(null);
    }

    protected void addIDTokenHandler(IDTokenHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding IDTokenHandler " + handler.getName());
        }
        OIDCServiceComponentHolder.getInstance().getIDTokenHandlers().add(handler);
    }

    protected void removeIDTokenHandler(IDTokenHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing IDTokenHandler " + handler.getName());
        }
        OIDCServiceComponentHolder.getInstance().getIDTokenHandlers().remove(handler);
    }
}
