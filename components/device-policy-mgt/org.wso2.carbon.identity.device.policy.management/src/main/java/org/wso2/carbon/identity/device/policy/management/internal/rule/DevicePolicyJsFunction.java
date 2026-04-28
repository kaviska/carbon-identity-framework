/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
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
import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationException;

import javax.servlet.http.HttpServletRequest;
import java.util.function.BiFunction;

/**
 * JS function implementation for device policy compliance check.
 * Implements BiFunction to be directly callable from JavaScript via GraalVM polyglot engine.
 * Parameters: JsBaseAuthenticationContext (authentication context), String (policy name).
 * Returns: empty string ("") if compliant, or a comma-separated string of failed field names if not compliant.
 */
public class DevicePolicyJsFunction implements BiFunction<JsBaseAuthenticationContext, String, String> {

    private static final Log LOG = LogFactory.getLog(DevicePolicyJsFunction.class);

    @Override
    @HostAccess.Export
    public String apply(JsBaseAuthenticationContext context, String policyName) {

        try {
            TransientObjectWrapper<HttpServletRequest> requestWrapper =
                    (TransientObjectWrapper<HttpServletRequest>) context.getWrapped()
                            .getProperty(FrameworkConstants.RequestAttribute.HTTP_REQUEST);
            HttpServletRequest request = requestWrapper.getWrapped();

            String tenantDomain = context.getWrapped().getTenantDomain();

            return new DevicePolicyEvaluator().evaluate(policyName, request, tenantDomain);

        } catch (PolicyManagementException e) {
            LOG.error("Error while evaluating device policy: " + policyName, e);
            return policyName + ":policy_error";
        } catch (RuleEvaluationException e) {
            LOG.error("Rule evaluation failed for device policy: " + policyName, e);
            return policyName + ":evaluation_error";
        }
    }
}
