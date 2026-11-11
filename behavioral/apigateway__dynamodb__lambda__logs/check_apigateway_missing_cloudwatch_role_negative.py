"""apigateway-missing-cloudwatch-role-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigateway-missing-cloudwatch-role-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_CWL_MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:e2e", "concern:metrics", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """With no account CloudWatch role, UpdateStage rejects enabling execution logging with
    BadRequestException; with a role carrying the managed policy the same call succeeds and the
    stage delivers execution log entries."""
    api_id = _create_mock_api(ctx)
    apigw = ctx.client("apigateway")

    # --- negative: no CloudWatch role configured on the account ---
    _clear_account_cwl_role(ctx)

    bad_stage = f"sim2realbad{api_id[:8]}"
    apigw.create_deployment(restApiId=api_id, stageName=bad_stage)
    code, message = _error_code(
        lambda: apigw.update_stage(
            restApiId=api_id,
            stageName=bad_stage,
            patchOperations=[{"op": "replace", "path": "/*/*/logging/loglevel", "value": "INFO"}],
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException enabling logging with no account CloudWatch role, got {code}: {message}"
    )
    assert message == "CloudWatch Logs role ARN must be set in account settings to enable logging", message

    # effect absent, via an independent read: the rejected UpdateStage never took.
    bad_settings = apigw.get_stage(restApiId=api_id, stageName=bad_stage).get("methodSettings", {})
    assert not bad_settings.get("*/*", {}).get("loggingLevel"), (
        f"stage logging level should be unset after the rejected UpdateStage, got {bad_settings}"
    )

    # --- positive control: same api, a fresh stage, a role with the managed policy ---
    good_role_arn = _create_apigw_role(ctx, policy_arns=[_CWL_MANAGED_POLICY])
    _set_account_cwl_role(ctx, good_role_arn)

    good_stage = f"sim2realgood{api_id[:8]}"
    apigw.create_deployment(restApiId=api_id, stageName=good_stage)
    apigw.update_stage(
        restApiId=api_id,
        stageName=good_stage,
        patchOperations=[{"op": "replace", "path": "/*/*/logging/loglevel", "value": "INFO"}],
    )
    good_level = apigw.get_stage(restApiId=api_id, stageName=good_stage)["methodSettings"]["*/*"]["loggingLevel"]
    assert good_level == "INFO", (
        f"expected the identical UpdateStage call to succeed once a role is set, got {good_level!r}"
    )
    good_log_group = f"API-Gateway-Execution-Logs_{api_id}/{good_stage}"
    ctx.on_cleanup(lambda: _delete_log_group_if_exists(ctx, good_log_group))
    # first-time activation of a just-set account CloudWatch role can lag behind
    # the update_account call succeeding, so a single early request may predate
    # the moment delivery actually starts; keep re-driving traffic so there is
    # always something recent in flight for the poll to observe.
    status, good_messages, sent_request_ids = _invoke_and_poll_logs(
        ctx, api_id, good_stage, good_log_group, timeout_s=220.0
    )
    assert status == 200
    assert sent_request_ids
    assert good_messages, f"positive control never produced execution logs in {good_log_group}"
    assert any(rid in msg for rid in sent_request_ids for msg in good_messages), (
        "positive control's own request ids never showed up in its execution logs"
    )


def _error_code(fn) -> tuple[str | None, str | None]:
    try:
        fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        error = response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _create_apigw_role(ctx: Any, policy_arns: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-apigw-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "apigateway.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        except Exception as exc:
            last_err = exc
            time.sleep(3)
    code = getattr(last_err, "response", {}).get("Error", {}).get("Code") if last_err else None
    msg = getattr(last_err, "response", {}).get("Error", {}).get("Message") if last_err else None
    raise AssertionError(f"{code}:{msg}")


def _clear_account_cwl_role(ctx: Any, timeout_s: float = 150.0) -> None:
    """Remove the account's cloudwatchRoleArn entirely (simulates "no CloudWatch
    role configured"). Restores whatever was there before on cleanup."""
    apigw = ctx.client("apigateway")
    prev = apigw.get_account().get("cloudwatchRoleArn")

    def _restore() -> None:
        apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": prev or ""}])

    ctx.on_cleanup(_restore)
    if not prev:
        return
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": ""}])
            return
        except Exception as exc:
            last_err = exc
            time.sleep(3)
    code = getattr(last_err, "response", {}).get("Error", {}).get("Code") if last_err else None
    msg = getattr(last_err, "response", {}).get("Error", {}).get("Message") if last_err else None
    raise AssertionError(f"clear cloudwatchRoleArn failed: {code}:{msg}")



def _create_mock_api(ctx: Any) -> str:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"), tags={"sim2real": CHECK}
    )["id"]
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


def _invoke_and_poll_logs(
    ctx: Any,
    api_id: str,
    stage_name: str,
    log_group_name: str,
    timeout_s: float = 220.0,
    refresh_s: float = 20.0,
    interval_s: float = 5.0,
):
    """Repeatedly invokes the stage while polling its execution log group, so a
    request always stays freshly in flight for the terminal read even if log
    delivery itself takes a while to start after the account role changed."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    sent_request_ids: set[str] = set()
    last_invoke = 0.0
    status: int | None = None
    while time.monotonic() < deadline:
        if time.monotonic() - last_invoke > refresh_s:
            status, _, request_id = _invoke(ctx, api_id, stage_name)
            if request_id:
                sent_request_ids.add(request_id)
            last_invoke = time.monotonic()
        try:
            events: list[str] = []
            paginator = logs.get_paginator("filter_log_events")
            for page in paginator.paginate(logGroupName=log_group_name):
                events.extend(e["message"] for e in page.get("events", []))
            if any(rid in msg for rid in sent_request_ids for msg in events):
                return status, events, sent_request_ids
        except logs.exceptions.ResourceNotFoundException:
            pass
        time.sleep(interval_s)
    return status, [], sent_request_ids


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
