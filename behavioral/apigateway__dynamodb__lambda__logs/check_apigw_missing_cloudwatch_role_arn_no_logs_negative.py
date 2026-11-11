"""apigw-missing-cloudwatch-role-arn-no-logs-negative."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigw-missing-cloudwatch-role-arn-no-logs-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """Without an account CloudWatch role ARN, UpdateStage rejects enabling execution logging with
    BadRequestException; with a valid role ARN the same call succeeds and traffic is logged."""
    lambda_role_arn = _create_lambda_execution_role(ctx)
    fn = _create_echo_lambda(ctx, lambda_role_arn)
    api = _create_rest_api_with_lambda_proxy(ctx, fn)
    stage_name = "prod"
    _deploy_stage(ctx, api["id"], stage_name)
    log_group = f"API-Gateway-Execution-Logs_{api['id']}/{stage_name}"
    ctx.on_cleanup(lambda: _delete_log_group_quiet(ctx, log_group))

    original_role = _clear_account_cw_role(ctx)

    # broken condition: no account cloudWatchRoleArn -> API Gateway refuses to enable logging at
    # all for this stage, failing the UpdateStage call itself.
    apigw = ctx.client("apigateway")
    try:
        apigw.update_stage(
            restApiId=api["id"],
            stageName=stage_name,
            patchOperations=[{"op": "replace", "path": "/*/*/logging/loglevel", "value": "INFO"}],
        )
        raised = False
    except apigw.exceptions.BadRequestException:
        raised = True
    assert raised, "expected UpdateStage to reject enabling logging with no account cloudWatchRoleArn"

    # effect-absent: an independent read (GetStage, not the rejected call's own response) confirms
    # the patch never took effect -- the rejection is a config-time refusal, not a silent no-op.
    stage_after_rejection = apigw.get_stage(restApiId=api["id"], stageName=stage_name)
    rejected_level = stage_after_rejection.get("methodSettings", {}).get("*/*", {}).get("loggingLevel", "OFF")
    assert rejected_level == "OFF", (
        f"expected no logging level to be applied after the rejected UpdateStage, got {rejected_level!r}"
    )

    # positive control: fix the ONE broken condition (set a valid role ARN) and observe the SAME
    # UpdateStage call succeed, followed by real log delivery for real traffic.
    cw_role_arn = _create_apigw_cloudwatch_role(ctx)
    _set_account_cw_role(ctx, cw_role_arn)
    ctx.on_cleanup(lambda: _set_account_cw_role(ctx, original_role or ""))
    _set_execution_logging(ctx, api["id"], stage_name, level="INFO")

    url = f"{ctx.rest_api_url(api['id'], stage_name)}/echo"
    status, _ = _wait_for_200(url, timeout_s=60)
    assert status == 200, f"expected the echo route to keep serving 200 after the fix, got {status}"
    events2 = _poll_log_events_with_traffic(ctx, log_group, url, timeout_s=220, min_events=1)
    assert len(events2) > 0, "positive control: logs never delivered even with a valid role ARN"


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


def _clear_account_cw_role(ctx) -> str | None:
    """Clears the account cloudWatchRoleArn, returning the PREVIOUS value so a caller can restore
    it, and registers a best-effort restore cleanup as a safety net."""
    apigw = ctx.client("apigateway")
    original = apigw.get_account().get("cloudwatchRoleArn")
    ctx.on_cleanup(lambda: _set_account_cw_role(ctx, original or ""))
    apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": ""}])
    return original


def _set_account_cw_role(ctx, role_arn: str) -> None:
    apigw = ctx.client("apigateway")
    deadline = time.monotonic() + 60
    last_exc = None
    while time.monotonic() < deadline:
        try:
            apigw.update_account(
                patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}]
            )
            return
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
        except Exception as exc:  # noqa: BLE001
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
        patchOperations=[{"op": "replace", "path": "/*/*/logging/loglevel", "value": level}],
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
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
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
