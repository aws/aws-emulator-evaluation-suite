"""apigateway-log-group-resource-policy-missing-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigateway-log-group-resource-policy-missing-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

# NOTE on interpretation: CloudWatch Logs resource policies (logs:PutResourcePolicy)
# explicitly only apply to calls made directly by AWS service principals (e.g.
# Route 53, VPC Flow Logs) -- they are documented as NOT enforced for IAM
# roles/users, and API Gateway always writes logs through an assumed IAM role, so a
# missing/absent CloudWatch Logs resource policy has no bearing on API Gateway
# delivery. The real, verifiable analogue of "the target log group does not grant
# API Gateway permission to write" is the CloudWatch role's own IDENTITY policy not
# granting PutLogEvents against that specific log group ARN -- tested here via an
# explicit per-resource Deny that overrides the role's otherwise-blanket Allow.


@tags("axis:negative-delivery", "cap:c2", "cap:c7", "concern:data-plane", "concern:metrics", "dp:endpoint", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """A stage whose execution log group is covered by an explicit Deny in the CloudWatch role gets no
    log entries, while a second stage on the same API outside the Deny gets its logs delivered."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    apigw = ctx.client("apigateway")
    logs = ctx.client("logs")

    api_id = _create_mock_api(ctx)
    bad_stage = f"sim2realdeny{api_id[:8]}"
    good_stage = f"sim2realallow{api_id[:8]}"

    bad_log_group = f"API-Gateway-Execution-Logs_{api_id}/{bad_stage}"
    bad_log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{bad_log_group}"
    logs.create_log_group(logGroupName=bad_log_group, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: _delete_log_group_if_exists(ctx, bad_log_group))

    role_arn = _create_apigw_role_with_denied_resource(ctx, denied_log_group_arn=bad_log_group_arn)
    _set_account_cwl_role(ctx, role_arn)

    apigw.create_deployment(restApiId=api_id, stageName=bad_stage)
    apigw.update_stage(
        restApiId=api_id,
        stageName=bad_stage,
        patchOperations=[{"op": "replace", "path": "/*/*/logging/loglevel", "value": "INFO"}],
    )
    status, _, request_id = _invoke(ctx, api_id, bad_stage)
    assert status == 200, "API must keep serving even though its log group write is explicitly denied"
    assert request_id, f"no x-amzn-RequestId header on the {bad_stage} invocation response"

    bad_messages = _poll_log_group_messages(ctx, bad_log_group, timeout_s=90)
    assert bad_messages == [], (
        f"execution logs appeared in {bad_log_group} despite an explicit Deny on "
        f"PutLogEvents/CreateLogStream for that exact log group ARN: {bad_messages[:3]}"
    )

    # --- positive control: same role, a different stage/log group NOT covered by the Deny ---
    apigw.create_deployment(restApiId=api_id, stageName=good_stage)
    apigw.update_stage(
        restApiId=api_id,
        stageName=good_stage,
        patchOperations=[{"op": "replace", "path": "/*/*/logging/loglevel", "value": "INFO"}],
    )
    status, _, good_request_id = _invoke(ctx, api_id, good_stage)
    assert status == 200, f"expected 200 from the positive-control stage {good_stage}, got {status}"
    assert good_request_id, f"no x-amzn-RequestId header on the {good_stage} invocation response"

    good_log_group = f"API-Gateway-Execution-Logs_{api_id}/{good_stage}"
    ctx.on_cleanup(lambda: _delete_log_group_if_exists(ctx, good_log_group))
    good_messages = _poll_log_group_messages(ctx, good_log_group, timeout_s=150)
    assert good_messages, f"positive control never produced execution logs in {good_log_group}"
    assert any(good_request_id in msg for msg in good_messages), (
        "positive control's own request id never showed up in its execution logs"
    )


def _create_apigw_role_with_denied_resource(ctx: Any, denied_log_group_arn: str) -> str:
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_iam_role(ctx, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BroadAllow",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                ],
                "Resource": "*",
            },
            {
                "Sid": "DenyOneLogGroup",
                "Effect": "Deny",
                "Action": ["logs:PutLogEvents", "logs:CreateLogStream"],
                "Resource": [denied_log_group_arn, f"{denied_log_group_arn}:*"],
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))
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
    raise AssertionError(f"apigateway account never accepted cloudwatchRoleArn={role_arn}: {last_err}")


def _create_mock_api(ctx: Any) -> str:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"), tags={"sim2real:managed": "true"}
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


def _poll_log_group_messages(ctx: Any, log_group_name: str, timeout_s: float = 150.0, interval_s: float = 5.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            events: list[str] = []
            paginator = logs.get_paginator("filter_log_events")
            for page in paginator.paginate(logGroupName=log_group_name):
                events.extend(e["message"] for e in page.get("events", []))
            if events:
                return events
        except logs.exceptions.ResourceNotFoundException:
            pass
        except Exception:
            pass
        time.sleep(interval_s)
    return []


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
