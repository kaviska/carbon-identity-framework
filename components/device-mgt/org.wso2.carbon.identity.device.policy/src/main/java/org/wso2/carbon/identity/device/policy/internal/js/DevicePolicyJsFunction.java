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

package org.wso2.carbon.identity.device.policy.internal.js;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.base.JsBaseAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.TransientObjectWrapper;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.device.policy.internal.component.DevicePolicyComponentServiceHolder;
import org.wso2.carbon.identity.device.policy.internal.jwt.DeviceTokenExtractor;
import org.wso2.carbon.identity.policy.management.api.exception.PolicyManagementClientException;
import org.wso2.carbon.identity.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationException;

import java.util.Map;
import java.util.function.BiFunction;

import javax.servlet.http.HttpServletRequest;

/**
 * JS function for device policy compliance check, registered as {@code isDevicePolicyCompliant}.
 * Device token is resolved from query params first (redirect flows), then X-Device-Token header (headless flows).
 */
public class DevicePolicyJsFunction implements BiFunction<JsBaseAuthenticationContext, String, String> {

    private static final Log LOG = LogFactory.getLog(DevicePolicyJsFunction.class);
    private static final String DEVICE_TOKEN_HEADER = "X-Device-Token";

    @Override
    @HostAccess.Export
    public String apply(JsBaseAuthenticationContext context, String policyName) {

        try {
            String tenantDomain = context.getWrapped().getTenantDomain();

            // Resolve the device token from the X-Device-Token header on the current request — never
            // from the URL. Works for both headless/API auth (the app calls the auth API with the
            // header) and redirect flows (the app resumes /commonauth with the header during the
            // device prompt step). Keeping it out of the URL avoids leakage via access logs, browser
            // history and the Referer header.
            String deviceToken = null;
            TransientObjectWrapper<HttpServletRequest> requestWrapper =
                    (TransientObjectWrapper<HttpServletRequest>) context.getWrapped()
                            .getProperty(FrameworkConstants.RequestAttribute.HTTP_REQUEST);
            if (requestWrapper != null && requestWrapper.getWrapped() != null) {
                deviceToken = requestWrapper.getWrapped().getHeader(DEVICE_TOKEN_HEADER);
            }

            if (deviceToken == null || deviceToken.isEmpty()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No device token found for policy: " + policyName
                            + ". Checked the X-Device-Token header.");
                }
                return policyName + ":no_device_token";
            }

            Map<String, Object> deviceData = new DeviceTokenExtractor().extractFromToken(deviceToken, tenantDomain);

            String appId = context.getWrapped().getServiceProviderResourceId();
            DevicePolicyComponentServiceHolder holder = DevicePolicyComponentServiceHolder.getInstance();
            holder.getIntegrityDataEnricher().enrich(deviceData, appId, tenantDomain);

            return holder.getDevicePolicyEvaluator().evaluate(policyName, deviceData, tenantDomain);

        } catch (PolicyManagementClientException e) {
            // Expected client-side rejection (invalid signature, expired/unregistered device,
            // malformed token). Caused by client input, not a server fault — log at debug without a
            // stack trace and treat the device as non-compliant.
            if (LOG.isDebugEnabled()) {
                LOG.debug("Device token rejected for policy " + policyName + ": " + e.getMessage());
            }
            return policyName + ":invalid_device_token";
        } catch (PolicyManagementException e) {
            LOG.error("Error while evaluating device policy: " + policyName, e);
            return policyName + ":policy_error";
        } catch (RuleEvaluationException e) {
            LOG.error("Rule evaluation failed for device policy: " + policyName, e);
            return policyName + ":evaluation_error";
        }
    }

}
