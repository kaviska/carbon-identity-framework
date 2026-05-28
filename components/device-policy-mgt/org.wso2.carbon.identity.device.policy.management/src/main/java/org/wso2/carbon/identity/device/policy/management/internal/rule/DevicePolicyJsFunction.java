/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.device.policy.management.internal.rule;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.base.JsBaseAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.TransientObjectWrapper;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.internal.component.DevicePolicyMgtComponentServiceHolder;
import org.wso2.carbon.identity.device.policy.management.internal.jwt.DeviceTokenExtractor;
import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationException;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.function.BiFunction;

import javax.servlet.http.HttpServletRequest;

/**
 * JS function implementation for device policy compliance check.
 * Implements BiFunction to be directly callable from JavaScript via GraalVM polyglot engine.
 * Parameters: JsBaseAuthenticationContext (authentication context), String (policy name).
 * Returns: null if compliant, or a comma-separated string of failed field names if not compliant.
 *
 * Device token resolution order:
 * 1. context.getQueryParams() — works for all redirect-based flows (OAuth2, SAML, WS-Fed)
 *    when device_token is sent as a query param in the initial authorize request.
 * 2. X-Device-Token header — works for API-based (headless) authn flows.
 */
public class DevicePolicyJsFunction implements BiFunction<JsBaseAuthenticationContext, String, String> {

    private static final Log LOG = LogFactory.getLog(DevicePolicyJsFunction.class);
    private static final String DEVICE_TOKEN_PARAM = "device_token";
    private static final String DEVICE_TOKEN_HEADER = "X-Device-Token";

    @Override
    @HostAccess.Export
    public String apply(JsBaseAuthenticationContext context, String policyName) {

        try {
            String tenantDomain = context.getWrapped().getTenantDomain();

            // Step 1 — try context queryParams (redirect flows: OAuth2, SAML, WS-Fed)
            // device_token sent as query param in authorize request is permanently stored here.
            String deviceToken = extractFromQueryParams(context.getWrapped().getQueryParams());

            // Step 2 — fallback to X-Device-Token header (API authn / headless flow)
            if (deviceToken == null || deviceToken.isEmpty()) {
                TransientObjectWrapper<HttpServletRequest> requestWrapper =
                        (TransientObjectWrapper<HttpServletRequest>) context.getWrapped()
                                .getProperty(FrameworkConstants.RequestAttribute.HTTP_REQUEST);
                if (requestWrapper != null && requestWrapper.getWrapped() != null) {
                    deviceToken = requestWrapper.getWrapped().getHeader(DEVICE_TOKEN_HEADER);
                }
            }

            if (deviceToken == null || deviceToken.isEmpty()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No device token found for policy: " + policyName
                            + ". Checked context queryParams and X-Device-Token header.");
                }
                return policyName + ":no_device_token";
            }

            Map<String, Object> deviceData = new DeviceTokenExtractor().extractFromToken(deviceToken, tenantDomain);

            String appId = context.getWrapped().getServiceProviderResourceId();
            DevicePolicyMgtComponentServiceHolder holder = DevicePolicyMgtComponentServiceHolder.getInstance();
            holder.getIntegrityDataEnricher().enrich(deviceData, appId, tenantDomain);

            return holder.getDevicePolicyEvaluator().evaluate(policyName, deviceData, tenantDomain);

        } catch (PolicyManagementException e) {
            LOG.error("Error while evaluating device policy: " + policyName, e);
            return policyName + ":policy_error";
        } catch (RuleEvaluationException e) {
            LOG.error("Rule evaluation failed for device policy: " + policyName, e);
            return policyName + ":evaluation_error";
        }
    }

    /**
     * Extracts the device_token value from a URL query string.
     * e.g. "client_id=my-app&device_token=eyJ...&scope=openid" → "eyJ..."
     */
    private String extractFromQueryParams(String queryString) {

        if (queryString == null || queryString.isEmpty()) {
            return null;
        }
        for (String pair : queryString.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                try {
                    String key = URLDecoder.decode(kv[0].trim(), StandardCharsets.UTF_8.name());
                    if (DEVICE_TOKEN_PARAM.equals(key)) {
                        return URLDecoder.decode(kv[1].trim(), StandardCharsets.UTF_8.name());
                    }
                } catch (UnsupportedEncodingException e) {
                    LOG.warn("Failed to decode query param while extracting device token: " + kv[0]);
                }
            }
        }
        return null;
    }
}
