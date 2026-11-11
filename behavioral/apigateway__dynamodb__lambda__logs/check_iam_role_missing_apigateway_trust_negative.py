"""iam-role-missing-apigateway-trust-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-missing-apigateway-trust-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:e2e", "concern:metrics", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """UpdateAccount rejects a CloudWatch role that does not trust apigateway.amazonaws.com with
    BadRequestException; a role that trusts it is accepted and execution logs are delivered."""

    iam = ctx.client("iam")
    apigw = ctx.client("apigateway")
    logs = ctx.client("logs")

    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
    original_role_arn = apigw.get_account().get("cloudwatchRoleArn")
    ctx.on_cleanup(lambda: _restore_account_role(apigw, original_role_arn))

    # --- negative: role trusts lambda.amazonaws.com, NOT apigateway.amazonaws.com ---
    bad_role_name = ctx.unique_name("sim2real-behav-apigw-badtrust-")
    bad_trust = _trust_policy("lambda.amazonaws.com")
    bad_role_arn = iam.create_role(
        RoleName=bad_role_name, AssumeRolePolicyDocument=json.dumps(bad_trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))
    iam.attach_role_policy(RoleName=bad_role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=bad_role_name, PolicyArn=policy_arn))

    # UpdateAccount validates the trust policy server-side and rejects a role
    # that does not trust apigateway.amazonaws.com — retry only on transient
    # errors (IAM propagation), but a persistent BadRequestException about the
    # trust/permissions is the expected terminal outcome.
    bad_err = _expect_update_account_rejected(apigw, bad_role_arn, timeout_s=60.0)
    bad_code = bad_err.response["Error"]["Code"]
    bad_message = bad_err.response["Error"]["Message"]
    assert bad_code == "BadRequestException", (
        f"expected BadRequestException for a role missing the apigateway.amazonaws.com "
        f"trust principal, got {bad_code}: {bad_message}"
    )
    assert bad_message == (
        "The role ARN does not have required permissions configured. Please grant trust "
        "permission for API Gateway and add the required role policy."
    ), bad_message

    # the rejected call must not have taken effect -- an independent read proves the
    # account's role binding is exactly what it was before the rejected attempt.
    unaffected_role_arn = apigw.get_account().get("cloudwatchRoleArn")
    assert unaffected_role_arn == original_role_arn, (
        f"cloudwatchRoleArn changed despite UpdateAccount being rejected: expected it to "
        f"remain {original_role_arn!r}, got {unaffected_role_arn!r}"
    )

    # --- positive control: role trusts apigateway.amazonaws.com, logs delivered ---
    good_role_name = ctx.unique_name("sim2real-behav-apigw-goodtrust-")
    good_trust = _trust_policy("apigateway.amazonaws.com")
    good_role_arn = iam.create_role(
        RoleName=good_role_name, AssumeRolePolicyDocument=json.dumps(good_trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))
    iam.attach_role_policy(RoleName=good_role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=good_role_name, PolicyArn=policy_arn))

    _retry_update_account(apigw, good_role_arn, timeout_s=90.0)
    _poll_until(
        lambda: apigw.get_account().get("cloudwatchRoleArn"),
        lambda v: v == good_role_arn,
        timeout_s=30.0,
        interval_s=2.0,
    )

    good_api_id, good_stage = _build_logging_api(ctx, apigw, "INFO")
    good_url = f"{ctx.rest_api_url(good_api_id, good_stage)}/echo"
    good_log_group = f"API-Gateway-Execution-Logs_{good_api_id}/{good_stage}"
    good_events = _invoke_until_log_events(good_url, logs, good_log_group, timeout_s=180.0)
    assert len(good_events) > 0, (
        f"positive control never produced execution log events in {good_log_group} even "
        f"though the account role trusts apigateway.amazonaws.com"
    )


def _expect_update_account_rejected(apigw, role_arn: str, timeout_s: float = 60.0):
    """Retries UpdateAccount only on throttling; returns the terminal ClientError
    once the rejection is not a transient one (i.e. it names the trust/permission
    problem), or raises AssertionError if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            apigw.update_account(
                patchOperations=[
                    {"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}
                ]
            )
            raise AssertionError(
                "update_account unexpectedly succeeded with a role missing the "
                "apigateway.amazonaws.com trust principal"
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "ThrottlingException"):
                time.sleep(3.0)
                continue
            return err
    raise AssertionError(f"update_account never returned a terminal error within {timeout_s}s")


def _restore_account_role(apigw, role_arn: str | None) -> None:
    """Put the account's CloudWatch role back to exactly what this check read (none: unset)."""
    apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn or ""}])


def _trust_policy(service: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _retry_update_account(apigw, role_arn: str, timeout_s: float = 90.0) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            apigw.update_account(
                patchOperations=[
                    {"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}
                ]
            )
            return
        except ClientError as err:
            last_err = err
            time.sleep(3.0)
    raise AssertionError(f"update_account never succeeded within {timeout_s}s: {last_err}")


def _build_logging_api(ctx, apigw, logging_level: str) -> tuple[str, str]:
    api_name = ctx.unique_name("sim2real-behav-apigw-")
    api = apigw.create_rest_api(name=api_name)
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="echo")
    resource_id = resource["id"]

    apigw.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"ok": true}'},
    )

    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/*/*/logging/loglevel", "value": logging_level},
        ],
    )
    return api_id, stage_name


def _poll_invoke_ok(url: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(f"API never returned 200 within {timeout_s}s: {last_exc}")


def _invoke_until_log_events(
    url: str, logs, log_group: str, timeout_s: float = 180.0, interval_s: float = 5.0
):
    """Repeatedly invokes the API and checks for execution log events. A fresh
    role/policy attachment can take a while to propagate through API Gateway's
    internal caches, so a single invoke right after granting the policy can
    silently fail to push logs — retrying the invoke itself (not just polling
    logs) lets the pipeline self-heal once the permissions are live."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=10):
                pass
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            pass

        try:
            streams = logs.describe_log_streams(logGroupName=log_group)["logStreams"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            streams = []
        for stream in streams:
            events = logs.get_log_events(
                logGroupName=log_group, logStreamName=stream["logStreamName"]
            )["events"]
            if events:
                return events
        time.sleep(interval_s)
    return []


def _poll_for_log_events(logs, log_group: str, timeout_s: float = 45.0, interval_s: float = 5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            streams = logs.describe_log_streams(logGroupName=log_group)["logStreams"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            streams = []
        for stream in streams:
            events = logs.get_log_events(
                logGroupName=log_group, logStreamName=stream["logStreamName"]
            )["events"]
            if events:
                return events
        time.sleep(interval_s)
    return []


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
