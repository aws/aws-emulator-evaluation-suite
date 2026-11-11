"""update-account-cloudwatch-role-enforced-for-logging."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-account-cloudwatch-role-enforced-for-logging"
GROUP = "server-side"
SERVICES = ["apigateway"]

_CWL_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """Setting the account's cloudwatchRoleArn is enforced server-side: enabling stage
    execution logging is rejected while the account has no role, and becomes usable
    immediately after UpdateAccount sets a valid role -- with no separate propagation call."""
    apigw = ctx.client("apigateway")
    iam = ctx.client("iam")

    original_arn = apigw.get_account().get("cloudwatchRoleArn") or ""

    def _restore_account() -> None:
        apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": original_arn}])

    ctx.on_cleanup(_restore_account)

    # Baseline: no CloudWatch role configured for the account.
    apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": ""}])
    assert not apigw.get_account().get("cloudwatchRoleArn")

    api_id, stage_name = _create_minimal_deployed_api(ctx, apigw)

    err = _client_error(
        lambda: apigw.update_stage(
            restApiId=api_id,
            stageName=stage_name,
            patchOperations=[{"op": "replace", "path": "/*/*/logging/loglevel", "value": "INFO"}],
        )
    )
    assert err.get("Code") == "BadRequestException", (
        f"expected BadRequestException with no account role, got {err.get('Code')!r}"
    )
    assert err.get("Message") == "CloudWatch Logs role ARN must be set in account settings to enable logging", (
        f"expected the exact missing-account-role refusal message, got {err.get('Message')!r}"
    )

    rejected_stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    rejected_level = rejected_stage.get("methodSettings", {}).get("*/*", {}).get("loggingLevel")
    assert rejected_level != "INFO", (
        f"rejected update_stage must not have taken effect, but loggingLevel={rejected_level!r}"
    )

    role_name = ctx.unique_name("sim2real-apigw-cwl-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "apigateway.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CWL_POLICY_ARN)

    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_CWL_POLICY_ARN))

    # A freshly created role is refused by UpdateAccount until IAM propagates its trust policy;
    # poll bounded on the same deadline on every target, and fail loudly past it.
    role_deadline = time.monotonic() + 90
    while True:
        try:
            apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}])
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "BadRequestException" or time.monotonic() >= role_deadline:
                raise
            time.sleep(5)
    assert apigw.get_account().get("cloudwatchRoleArn") == role_arn, "account did not immediately reflect new role"

    # IAM role/policy propagation can lag a few seconds; poll bounded for the enable to succeed
    # without touching the account setting again (proving apigateway itself needed no extra call).
    last_code = "unset"
    deadline = time.monotonic() + 30
    succeeded = False
    while time.monotonic() < deadline:
        try:
            apigw.update_stage(
                restApiId=api_id,
                stageName=stage_name,
                patchOperations=[{"op": "replace", "path": "/*/*/logging/loglevel", "value": "INFO"}],
            )
        except ClientError as exc:
            last_code = exc.response.get("Error", {}).get("Code")
            time.sleep(3)
            continue
        succeeded = True
        break

    assert succeeded, f"enabling stage logging never succeeded after account role was set, last error: {last_code}"

    stage = apigw.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage["methodSettings"]["*/*"]["loggingLevel"] == "INFO"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_minimal_deployed_api(ctx, apigw) -> tuple[str, str]:
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"), tags={"sim2real:managed": "true"})
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
                          requestTemplates={"application/json": '{"statusCode": 200}'})
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
                                   responseTemplates={"application/json": '{"message": "ok"}'})

    deployment = apigw.create_deployment(restApiId=api_id)
    stage_name = ctx.unique_name("sim2real-stage-")
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment["id"])
    return api_id, stage_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
