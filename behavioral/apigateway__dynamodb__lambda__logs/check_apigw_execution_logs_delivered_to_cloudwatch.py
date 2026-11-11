"""apigw-execution-logs-delivered-to-cloudwatch."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigw-execution-logs-delivered-to-cloudwatch"
GROUP = "log-delivery"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "dp:endpoint", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """Enabling stage execution logging (loglevel INFO) delivers real request-trace lines to the
    API-Gateway-managed CloudWatch log group after a real invocation through the deployed stage."""
    cw_role_arn = _create_apigw_cloudwatch_role(ctx)
    _swap_account_cw_role(ctx, cw_role_arn)

    lambda_role_arn = _create_lambda_execution_role(ctx)
    fn = _create_echo_lambda(ctx, lambda_role_arn)
    api = _create_rest_api_with_lambda_proxy(ctx, fn)
    stage_name = "prod"
    _deploy_stage(ctx, api["id"], stage_name)
    _set_execution_logging(ctx, api["id"], stage_name, level="INFO")

    url = f"{ctx.rest_api_url(api['id'], stage_name)}/echo"
    status, _ = _wait_for_200(url, timeout_s=60)
    assert status == 200

    log_group = f"API-Gateway-Execution-Logs_{api['id']}/{stage_name}"
    ctx.on_cleanup(lambda: _delete_log_group_quiet(ctx, log_group))
    # First-time activation of an account-level CloudWatch role can take a while for API Gateway's
    # log-push pipeline to actually start working, even though update_account/update_stage already
    # returned success. Keep sending fresh traffic while polling so we always have a recent request
    # once delivery kicks in, and budget most of the check's real-AWS time allowance here.
    events = _poll_log_events_with_traffic(ctx, log_group, url, timeout_s=230, min_events=1)
    assert len(events) > 0, f"no execution log events delivered to {log_group}"
    messages = "\n".join(e["message"] for e in events)
    assert "Method completed with status: 200" in messages, messages[:2000]


_LAMBDA_ECHO_CODE = (
    "import json\n"
    "def handler(event, context):\n"
    "    return {'statusCode': 200, 'headers': {'Content-Type': 'application/json'},"
    " 'body': json.dumps({'ok': True, 'path': event.get('path')})}\n"
)


def _trust_policy(service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def _create_apigw_cloudwatch_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-apigwcw-")
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust_policy("apigateway.amazonaws.com"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return role_arn


def _swap_account_cw_role(ctx, new_role_arn: str | None) -> str | None:
    """Sets the account-level cloudWatchRoleArn, returning the PREVIOUS value, and registers a
    cleanup that restores it. IAM/STS need a little time to propagate before API Gateway can
    successfully assume the role, so we retry the set for a bit."""
    apigw = ctx.client("apigateway")
    original = apigw.get_account().get("cloudwatchRoleArn")

    def _restore():
        apigw.update_account(
            patchOperations=[
                {"op": "replace", "path": "/cloudwatchRoleArn", "value": original or ""}
            ]
        )

    ctx.on_cleanup(_restore)
    deadline = time.monotonic() + 60
    last_exc = None
    while time.monotonic() < deadline:
        try:
            apigw.update_account(
                patchOperations=[
                    {"op": "replace", "path": "/cloudwatchRoleArn", "value": new_role_arn or ""}
                ]
            )
            return original
        except Exception as exc:  # noqa: BLE001 — role not yet assumable, retry
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"could not set account cloudWatchRoleArn: {last_exc}")


def _create_lambda_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambdaexec-")
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust_policy("lambda.amazonaws.com"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return role_arn


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_echo_lambda(ctx, role_arn: str) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-echo-")
    deadline = time.monotonic() + 90
    resp = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip_bytes(_LAMBDA_ECHO_CODE)},
                Timeout=10,
                Tags={"sim2real": CHECK},
            )
            break
        except Exception as exc:  # noqa: BLE001 — role propagation
            last_exc = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded: {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if state == "Active":
            break
        time.sleep(2)
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_rest_api_with_lambda_proxy(ctx, fn: dict) -> dict:
    apigw = ctx.client("apigateway")
    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="echo")["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"{fn['arn']}/invocations"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=uri,
    )
    source_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*"
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId=ctx.unique_name("sim2real-perm-"),
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )
    return {"id": api_id, "resource_id": resource_id}


def _deploy_stage(ctx, api_id: str, stage_name: str) -> None:
    apigw = ctx.client("apigateway")
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)


def _set_execution_logging(ctx, api_id: str, stage_name: str, level: str) -> None:
    apigw = ctx.client("apigateway")
    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/*/*/logging/loglevel", "value": level},
        ],
    )


def _wait_for_200(url: str, timeout_s: float = 180) -> tuple[int, bytes]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            last = (exc.code, exc.read())
            if exc.code == 200:
                return exc.code, last[1]
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # propagation / cold start, keep retrying
            last = exc
        time.sleep(5)
    raise AssertionError(f"GET {url} never returned 200 within {timeout_s}s (last={last!r})")


def _poll_log_events(
    ctx, log_group_name: str, start_time_ms: int, timeout_s: float = 180, min_events: int = 1
) -> list:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    events: list = []
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group_name, startTime=start_time_ms)
            events = resp.get("events", [])
            if len(events) >= min_events:
                return events
        except logs.exceptions.ResourceNotFoundException:
            pass
        time.sleep(5)
    return events


def _poll_log_events_with_traffic(
    ctx, log_group_name: str, url: str, timeout_s: float = 230, min_events: int = 1
) -> list:
    """Polls for delivered log events while periodically re-driving traffic through the stage.
    First-time activation of the account CloudWatch role can lag well behind the update_account
    call succeeding, so a single early request may predate the moment delivery actually starts;
    keep refreshing the marker request so we always have something recent in-flight to observe."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    start_time_ms = int(time.time() * 1000)
    events: list = []
    last_request = 0.0
    while time.monotonic() < deadline:
        if time.monotonic() - last_request > 20:
            try:
                req = urllib.request.Request(url, method="GET")
                urllib.request.urlopen(req, timeout=10)
            except (urllib.error.URLError, ConnectionError, TimeoutError):  # best-effort traffic refresh
                pass
            last_request = time.monotonic()
        try:
            resp = logs.filter_log_events(logGroupName=log_group_name, startTime=start_time_ms)
            events = resp.get("events", [])
            if len(events) >= min_events:
                return events
        except logs.exceptions.ResourceNotFoundException:
            pass
        time.sleep(5)
    return events


def _delete_log_group_quiet(ctx, name: str) -> None:
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
