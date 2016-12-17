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

package org.wso2.carbon.identity.inbound.auth.oauth2ext.grant.iwa.ntlm.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2ext.grant.iwa.ntlm.IWANTLMGrantFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant.AuthorizationGrantHandler;

@Component(
        name = "oauth2ext.grant.iwa.ntlm.component",
        immediate = true
)
public class IWANTLMGrantServiceComponent {

    private static Log log = LogFactory.getLog(IWANTLMGrantServiceComponent.class);

    @SuppressWarnings("unchecked")
    @Activate
    protected void activate(ComponentContext context) {

        try {

            ServiceRegistration saml2AssertionGrantHandler = context.getBundleContext().registerService(
                    AuthorizationGrantHandler.class.getName(), new IWANTLMGrantServiceComponent(), null);
            if (saml2AssertionGrantHandler != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" IWANTLMGrantHandler is registered");
                }
            } else {
                log.error("IWANTLMGrantHandler could not be registered");
            }

            ServiceRegistration  iwaNTLMGrantFactory = context.getBundleContext().registerService(
                    HttpIdentityRequestFactory.class.getName(), new IWANTLMGrantFactory(), null);
            if (iwaNTLMGrantFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" IWANTLMGrantHandler is registered");
                }
            } else {
                log.error("IWANTLMGrantHandler could not be registered");
            }

            if (log.isDebugEnabled()) {
                log.debug("IWANTLMGrantHandler bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error occurred while activating IWANTLMGrantHandler bundle", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("SAML2AssertionGrantHandler bundle is deactivated");
        }
    }

}
