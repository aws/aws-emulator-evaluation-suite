"""apigw-stage-logging-level-error-only."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigw-stage-logging-level-error-only"
GROUP = "log-delivery"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:endpoint", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """A stage at logging level OFF delivers no execution log entries for a request that fails with a 5xx;
    switching the same stage to ERROR delivers entries for the same failing request."""
    lambda_role_arn = _create_lambda_execution_role(ctx)
    fn = _create_boom_lambda(ctx, lambda_role_arn)
    api = _create_rest_api_with_lambda_proxy(ctx, fn)
    stage_name = "prod"
    _deploy_stage(ctx, api["id"], stage_name)
    log_group = f"API-Gateway-Execution-Logs_{api['id']}/{stage_name}"
    ctx.on_cleanup(lambda: _delete_log_group_quiet(ctx, log_group))

    # Set the account-level CloudWatch role FIRST and hold it constant across both phases below, so
    # the ONLY variable that changes between the OFF and ERROR observations is the stage's own
    # logging level -- not whether the account even has a CloudWatch role configured. Without this,
    # the OFF-phase absence would be equally explained by "no CloudWatch role yet" and would not
    # isolate the logging-level setting as the thing that gates delivery.
    cw_role_arn = _create_apigw_cloudwatch_role(ctx)
    _swap_account_cw_role(ctx, cw_role_arn)

    # the deployed method's Lambda always raises -> a genuine execution error (502), not just a
    # routing-level 4xx, so it exercises the real per-request execution log path.
    error_url = f"{ctx.rest_api_url(api['id'], stage_name)}/echo"

    # OFF (default, never enabled): drive a real erroring request, confirm zero log delivery.
    status, _ = _get_status(error_url, timeout_s=30)
    assert status >= 500
    off_events = _poll_log_events(ctx, log_group, int(time.time() * 1000) - 30_000, timeout_s=20, min_events=1)
    assert len(off_events) == 0, f"expected no execution log delivery while logging is OFF, got {off_events}"

    # positive control: flip the SAME stage to ERROR-level logging (no redeploy, same account
    # CloudWatch role as above), then observe the SAME kind of erroring request produce delivered
    # logs. First-time role activation can still lag, so keep re-driving the erroring request while
    # polling.
    _set_execution_logging(ctx, api["id"], stage_name, level="ERROR")
    events = _poll_log_events_with_traffic(ctx, log_group, error_url, timeout_s=220, min_events=1)
    assert len(events) > 0, "positive control: ERROR level never delivered logs for an erroring request"


_LAMBDA_BOOM_CODE = (
    "def handler(event, context):\n"
    "    raise RuntimeError('boom: deliberate execution error for the check')\n"
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
        RoleName=name, AssumeRolePolicyDocument=_trust_policy("apigateway.amazonaws.com")
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return role_arn


def _swap_account_cw_role(ctx, new_role_arn: str | None) -> str | None:
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
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"could not set account cloudWatchRoleArn: {last_exc}")


def _create_lambda_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambdaexec-")
    role_arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_trust_policy("lambda.amazonaws.com")
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


def _create_boom_lambda(ctx, role_arn: str) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-boom-")
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
                Code={"ZipFile": _zip_bytes(_LAMBDA_BOOM_CODE)},
                Timeout=10,
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

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"))["id"]
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


def _get_status(url: str, timeout_s: float = 30) -> tuple[int, bytes]:
    """Issues a single GET and returns whatever status comes back (including 4xx/5xx), retrying
    only on transport-level failures (DNS/connect), not on HTTP error responses."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # DNS/connect propagation, keep retrying
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"GET {url} never completed within {timeout_s}s (last={last_exc!r})")


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
