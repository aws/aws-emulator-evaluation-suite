"""apigateway-execution-logging-to-cloudwatch-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigateway-execution-logging-to-cloudwatch-positive"
GROUP = "execution-logging"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_CWL_MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "dp:endpoint", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """Enabling stage method-level execution logging (INFO) delivers request
    execution entries to the API-Gateway-managed CloudWatch log group, and a
    specific invocation's request id shows up in that group's log events.
    """
    role_arn = _create_apigw_cwl_role(ctx, [_CWL_MANAGED_POLICY])
    _set_account_cwl_role(ctx, role_arn)

    api_id = _create_mock_api(ctx)
    stage_name = f"sim2realexec{api_id[:8]}"
    apigw = ctx.client("apigateway")
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/*/*/logging/loglevel", "value": "INFO"},
        ],
    )

    log_group = f"API-Gateway-Execution-Logs_{api_id}/{stage_name}"
    ctx.on_cleanup(lambda: _delete_log_group_if_exists(ctx, log_group))

    # A freshly-attached account CloudWatch role can take a little while before
    # API Gateway's log delivery path actually honors it (the account-level
    # UpdateAccount call only validates that the role CAN be assumed, not that
    # delivery is already flowing) -- re-invoke on a budget until some
    # invocation's request id actually shows up in the execution log group,
    # rather than trusting a single invocation to land after full propagation.
    found_id, seen_ids, last_messages = _invoke_until_logged(ctx, api_id, stage_name, log_group, role_arn, timeout_s=240)
    assert found_id, (
        f"no invocation request id ever showed up in {log_group} (tried {seen_ids}); "
        f"last observed {len(last_messages)} unrelated message(s), sample={last_messages[:3]!r}"
    )


def _create_apigw_cwl_role(ctx: Any, policy_arns: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-apigw-cwl-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "apigateway.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_iam_role(ctx, role_name))
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    return role_arn


def _delete_iam_role(ctx: Any, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for p in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=p)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _set_account_cwl_role(ctx: Any, role_arn: str, timeout_s: float = 150.0) -> None:
    apigw = ctx.client("apigateway")
    prev = apigw.get_account().get("cloudwatchRoleArn")

    def _restore() -> None:
        apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": prev or ""}])

    ctx.on_cleanup(_restore)
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}])
            return
        except Exception as exc:  # role not yet assumable by apigateway (IAM propagation)
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"apigateway account never accepted cloudwatchRoleArn={role_arn}: {last_err}")


def _create_mock_api(ctx: Any) -> str:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="ping")["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"ok": true}'},
    )
    return api_id


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _invoke(ctx: Any, api_id: str, stage_name: str, path: str = "ping", timeout_s: float = 90.0):
    url = f"{ctx.rest_api_url(api_id, stage_name)}/{path}"
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    last_transient: tuple[int, bytes, Any] | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url), timeout=10, context=_ssl_context(ctx.http_verify)
            ) as resp:
                return resp.status, resp.read(), resp.headers.get("x-amzn-RequestId")
        except urllib.error.HTTPError as exc:
            body = exc.read()
            # a brand-new stage/deployment can 403/404 for a few seconds before it
            # becomes routable -- retry those instead of treating them as final.
            if exc.code in (403, 404):
                last_transient = (exc.code, body, exc.headers.get("x-amzn-RequestId"))
                time.sleep(2)
                continue
            return exc.code, body, exc.headers.get("x-amzn-RequestId")
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
            last_err = exc
            time.sleep(2)
    if last_transient is not None:
        return last_transient
    raise AssertionError(f"could not invoke {url}: {last_err}")


def _fetch_log_group_messages(ctx: Any, log_group_name: str) -> list[str]:
    logs = ctx.client("logs")
    try:
        events: list[str] = []
        paginator = logs.get_paginator("filter_log_events")
        for page in paginator.paginate(logGroupName=log_group_name):
            events.extend(e["message"] for e in page.get("events", []))
        return events
    except logs.exceptions.ResourceNotFoundException:
        return []


def _invoke_until_logged(
    ctx: Any, api_id: str, stage_name: str, log_group_name: str, role_arn: str, timeout_s: float = 240.0
) -> tuple[str | None, list[str], list[str]]:
    """Re-invoke the API on a budget, checking the execution/access log group
    after each call, until ANY invocation's request id (not just the one just
    made) shows up in the log group. Handles three things that can otherwise
    flake or falsely fail this check: (1) account CloudWatch role propagation
    lag, where the role is accepted by UpdateAccount but log delivery for the
    very next request can still silently no-op for a short window; (2)
    cloudwatchRoleArn being an account-wide singleton -- re-asserting our own
    role immediately before each invocation defends against another
    concurrently-running check temporarily pointing it elsewhere; and (3)
    per-request log delivery lag exceeding one invoke-then-check cycle, which
    means a request's own log lines routinely land only after a LATER
    invocation has already been made -- checking only the just-made request's
    id against that same cycle's poll is a receding horizon that can never
    catch up. Checking every seen id against the latest poll fixes that."""
    apigw = ctx.client("apigateway")
    deadline = time.monotonic() + timeout_s
    seen_ids: list[str] = []
    last_messages: list[str] = []
    while time.monotonic() < deadline:
        try:
            apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}])
        except Exception:
            pass
        status, _, request_id = _invoke(ctx, api_id, stage_name)
        assert status == 200, f"unexpected status {status} invoking mock API"
        assert request_id, "response did not carry an x-amzn-RequestId header"
        seen_ids.append(request_id)
        messages = _fetch_log_group_messages(ctx, log_group_name)
        if messages:
            last_messages = messages
        found = next((rid for rid in seen_ids if any(rid in msg for msg in messages)), None)
        if found is not None:
            return found, seen_ids, last_messages
        time.sleep(5)
    return None, seen_ids, last_messages




def _delete_log_group_if_exists(ctx: Any, log_group_name: str) -> None:
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
