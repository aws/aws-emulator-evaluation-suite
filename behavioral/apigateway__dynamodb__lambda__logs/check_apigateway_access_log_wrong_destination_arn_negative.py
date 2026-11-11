"""apigateway-access-log-wrong-destination-arn-negative."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigateway-access-log-wrong-destination-arn-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_CWL_MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "dp:endpoint", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """An access log destination naming a log group the CloudWatch role is denied logs:CreateLogGroup
    on is never created while the stage keeps serving 200, and a fresh destination without that Deny
    is created."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    api_id = _create_mock_api(ctx)
    apigw = ctx.client("apigateway")

    missing_group_name = ctx.unique_name("sim2real-behav-never-created-")
    missing_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{missing_group_name}"

    # --- negative: role has the full push permission set (passes account-level
    # validation) but an explicit per-resource Deny on CreateLogGroup for this
    # exact destination log group ---
    restricted_role_arn = _create_apigw_role_with_denied_create(ctx, denied_log_group_arn=missing_group_arn)
    _set_account_cwl_role(ctx, restricted_role_arn)

    bad_stage = f"sim2realwrongdst{api_id[:8]}"
    apigw.create_deployment(restApiId=api_id, stageName=bad_stage)
    apigw.update_stage(
        restApiId=api_id,
        stageName=bad_stage,
        patchOperations=[
            {"op": "replace", "path": "/accessLogSettings/destinationArn", "value": missing_group_arn},
            {"op": "replace", "path": "/accessLogSettings/format", "value": '{"requestId":"$context.requestId"}'},
        ],
    )
    status, _, request_id = _invoke(ctx, api_id, bad_stage)
    assert status == 200, "API must keep serving even though access log delivery cannot succeed"
    assert request_id, "expected x-amzn-RequestId header on the negative-path invoke response"

    assert _poll_log_group_created(ctx, missing_group_name, timeout_s=90) is False, (
        f"log group {missing_group_name} was created despite an explicit Deny on "
        "logs:CreateLogGroup for that exact destination ARN"
    )

    # --- positive control: same api, role with the full managed policy, a fresh destination ---
    good_role_arn = _create_apigw_role_with_denied_create(ctx, denied_log_group_arn=None)
    _set_account_cwl_role(ctx, good_role_arn)

    good_group_name = ctx.unique_name("sim2real-behav-autocreated-")
    good_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{good_group_name}"
    ctx.on_cleanup(lambda: _delete_log_group_if_exists(ctx, good_group_name))

    good_stage = f"sim2realgooddst{api_id[:8]}"
    apigw.create_deployment(restApiId=api_id, stageName=good_stage)
    apigw.update_stage(
        restApiId=api_id,
        stageName=good_stage,
        patchOperations=[
            {"op": "replace", "path": "/accessLogSettings/destinationArn", "value": good_group_arn},
            {"op": "replace", "path": "/accessLogSettings/format", "value": '{"requestId":"$context.requestId"}'},
        ],
    )
    status, _, good_request_id = _invoke(ctx, api_id, good_stage)
    assert status == 200, f"positive control: expected 200 from the good-destination stage, got {status}"
    assert good_request_id, "expected x-amzn-RequestId header on the positive-control invoke response"

    assert _poll_log_group_created(ctx, good_group_name, timeout_s=150) is True, (
        f"positive control never got its destination log group {good_group_name} created"
    )


def _create_apigw_role_with_denied_create(ctx: Any, denied_log_group_arn: str | None) -> str:
    """A role with the same broad push permissions as the AWS-managed
    AmazonAPIGatewayPushToCloudWatchLogs policy (required for the account-level
    cloudwatchRoleArn validation to accept it), optionally with an explicit
    per-resource Deny on logs:CreateLogGroup for one specific log group ARN."""
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
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_iam_role(ctx, role_name))
    statements = [
        {
            "Sid": "BroadAllow",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:GetLogEvents",
                "logs:FilterLogEvents",
            ],
            "Resource": "*",
        }
    ]
    if denied_log_group_arn:
        statements.append(
            {
                "Sid": "DenyCreateForOneLogGroup",
                "Effect": "Deny",
                "Action": "logs:CreateLogGroup",
                "Resource": [denied_log_group_arn, f"{denied_log_group_arn}:*"],
            }
        )
    doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(doc))
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


def _create_mock_api(ctx: Any) -> str:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-api-"), tags={"sim2real": CHECK})["id"]
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


def _poll_log_group_created(ctx: Any, log_group_name: str, timeout_s: float = 150.0, interval_s: float = 5.0) -> bool:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = logs.describe_log_groups(logGroupNamePrefix=log_group_name).get("logGroups", [])
        if any(g["logGroupName"] == log_group_name for g in groups):
            return True
        time.sleep(interval_s)
    return False


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
