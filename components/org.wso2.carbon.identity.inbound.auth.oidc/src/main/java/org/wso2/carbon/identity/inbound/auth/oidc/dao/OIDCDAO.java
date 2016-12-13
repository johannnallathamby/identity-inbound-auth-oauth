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

package org.wso2.carbon.identity.inbound.auth.oidc.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.inbound.auth.oidc.OIDC;
import org.wso2.carbon.identity.inbound.auth.oidc.exception.OIDCRuntimeException;
import org.wso2.carbon.identity.inbound.auth.oidc.internal.OIDCDataHolder;
import org.wso2.carbon.registry.api.Registry;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.api.Resource;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class OIDCDAO {

    private static Log log = LogFactory.getLog(OIDCDAO.class);

    public static void storeScopes(Map<String,String> scopes, String tenantDomain, int tenantId) throws
                                                                                          OIDCRuntimeException {
        try {
            Registry registry = OIDCDataHolder.getInstance().getRegistryService()
                    .getConfigSystemRegistry(tenantId);

            if (!registry.resourceExists(OIDC.OIDC_SCOPE_CONFIG_RESOURCE_PATH)) {

                Resource resource = registry.newResource();
                if (scopes.size() > 0) {
                    for (Map.Entry<String, String> entry : scopes.entrySet()) {
                        String valueStr = entry.getValue().toString();
                        resource.setProperty(entry.getKey(), valueStr);
                    }
                }
                registry.put(OIDC.OIDC_SCOPE_CONFIG_RESOURCE_PATH, resource);
            }
        } catch (RegistryException e) {
            throw OIDCRuntimeException.error("Error while storing scopes configuration for tenant domain: " +
                                               tenantDomain, e);
        }
    }

    public static List<String> getScopes(String tenantDomain, int tenantId) {

        try {
            Registry registry = OIDCDataHolder.getInstance().getRegistryService()
                    .getConfigSystemRegistry(tenantId);
            List<String> scopes = new ArrayList();
            if (registry.resourceExists(OIDC.OIDC_SCOPE_CONFIG_RESOURCE_PATH)) {
                Resource resource = registry.get(OIDC.OIDC_SCOPE_CONFIG_RESOURCE_PATH);
                Properties properties = resource.getProperties();
                Enumeration e = properties.propertyNames();
                while (e.hasMoreElements()) {
                    scopes.add((String) e.nextElement());
                }
            }
            return scopes;
        } catch (RegistryException e) {
            throw OIDCRuntimeException.error("Error while reading scopes configuration for tenant domain: " + OIDC
                    .OIDC_SCOPE_CONFIG_RESOURCE_PATH, e);
        }
    }
}
