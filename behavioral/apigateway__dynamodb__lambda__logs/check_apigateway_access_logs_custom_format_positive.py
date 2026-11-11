"""apigateway-access-logs-custom-format-positive."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigateway-access-logs-custom-format-positive"
GROUP = "execution-logging"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_CWL_MANAGED_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
)


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:endpoint",
    "plane:data", "resource:account-singleton:apigateway-account",
)
def run(ctx) -> None:
    """A custom accessLogSettings JSON format on a stage produces log entries in
    the destination log group whose fields match the actual invocation (status,
    http method, request id) rather than the raw $context template text.
    """
    role_arn = _create_apigw_cwl_role(ctx)
    _set_account_cwl_role(ctx, role_arn)

    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-access-logs-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    # describe_log_groups() returns an ARN with a trailing ":*" wildcard
    # suffix. API Gateway's destinationArn validation rejects the "*" character
    # ("Access log destination must only contain characters a-z, A-Z, 0-9, '_',
    # '-', '/', '.', '#', and ':'"), so build the ARN manually without it.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_name}"

    access_format = (
        '{"marker":"sim2real-access-log","requestId":"$context.requestId",'
        '"httpMethod":"$context.httpMethod","status":"$context.status",'
        '"resourcePath":"$context.resourcePath"}'
    )

    api_id = _create_mock_api(ctx)
    stage_name = f"sim2realacc{api_id[:8]}"
    apigw = ctx.client("apigateway")
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {
                "op": "replace",
                "path": "/accessLogSettings/destinationArn",
                "value": log_group_arn,
            },
            {
                "op": "replace",
                "path": "/accessLogSettings/format",
                "value": access_format,
            },
        ],
    )

    status, _, request_id = _invoke(ctx, api_id, stage_name)
    assert status == 200, f"expected 200 from mock GET /ping, got {status}"
    assert request_id, "response did not carry an x-amzn-RequestId header"

    # A freshly-attached account CloudWatch role can take a little while before
    # API Gateway's access-log delivery path actually honors it, so re-invoke on
    # a budget until some invocation's request id actually shows up as a parsed
    # JSON access log entry, rather than trusting the very first invocation.
    match, seen_ids = _invoke_until_matched(
        ctx, api_id, stage_name, log_group_name, timeout_s=240
    )
    assert match is not None, (
        f"no access log entry ever appeared for any of {seen_ids} in {log_group_name}"
    )
    assert match["marker"] == "sim2real-access-log", (
        f"expected marker literal, got {match!r}"
    )
    assert match["httpMethod"] == "GET", (
        f"expected httpMethod GET, got {match['httpMethod']!r}"
    )
    assert match["status"] == "200", f"expected status 200, got {match['status']!r}"
    assert match["resourcePath"] == "/ping", (
        f"expected resourcePath /ping, got {match['resourcePath']!r}"
    )




def _create_apigw_cwl_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-apigw-cwl-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "apigateway.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_iam_role(ctx, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CWL_MANAGED_POLICY)
    return role_arn


def _delete_iam_role(ctx: Any, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"
        ]:
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
        apigw.update_account(
            patchOperations=[
                {"op": "replace", "path": "/cloudwatchRoleArn", "value": prev or ""}
            ]
        )

    ctx.on_cleanup(_restore)
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            apigw.update_account(
                patchOperations=[
                    {"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}
                ]
            )
            return
        except Exception as exc:
            last_err = exc
            time.sleep(3)
    raise AssertionError(
        f"apigateway account never accepted cloudwatchRoleArn={role_arn}: {last_err}"
    )


def _create_mock_api(ctx: Any) -> str:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="ping"
    )["id"]
    apigw.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
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
    return api_id


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _invoke(
    ctx: Any, api_id: str, stage_name: str, path: str = "ping", timeout_s: float = 90.0
):
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


def _poll_log_group_json_events(
    ctx: Any, log_group_name: str, timeout_s: float = 150.0, interval_s: float = 5.0
):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            parsed = []
            paginator = logs.get_paginator("filter_log_events")
            for page in paginator.paginate(logGroupName=log_group_name):
                for e in page.get("events", []):
                    try:
                        parsed.append(json.loads(e["message"]))
                    except (json.JSONDecodeError, ValueError):
                        continue
            if parsed:
                return parsed
        except logs.exceptions.ResourceNotFoundException:
            pass
        except Exception:
            pass
        time.sleep(interval_s)
    return []


def _invoke_until_matched(
    ctx: Any,
    api_id: str,
    stage_name: str,
    log_group_name: str,
    timeout_s: float = 240.0,
):
    """Re-invoke the API until some request id seen so far appears in the parsed access log.

    The account CloudWatch role is set once by the caller (re-setting it each pass stalls delivery),
    and delivery lag exceeds one invoke-then-poll cycle, so every earlier request id is matched."""
    deadline = time.monotonic() + timeout_s
    seen_ids: list[str] = []
    while time.monotonic() < deadline:
        status, _, request_id = _invoke(ctx, api_id, stage_name)
        assert status == 200, f"unexpected status {status} invoking mock API"
        assert request_id, "response did not carry an x-amzn-RequestId header"
        seen_ids.append(request_id)
        entries = _poll_log_group_json_events(
            ctx, log_group_name, timeout_s=20.0, interval_s=4.0
        )
        match = next((e for e in entries if e.get("requestId") in seen_ids), None)
        if match is not None:
            return match, seen_ids
        time.sleep(5)
    return None, seen_ids


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
