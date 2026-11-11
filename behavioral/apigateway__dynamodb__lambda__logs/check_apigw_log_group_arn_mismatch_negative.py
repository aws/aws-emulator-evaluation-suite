"""apigw-log-group-arn-mismatch-negative."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags

CHECK = "apigw-log-group-arn-mismatch-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:control", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """UpdateStage rejects an access-log format without $context.requestId or $context.extendedRequestId
    with BadRequestException; with $context.requestId the same call succeeds and traffic is logged."""
    cw_role_arn = _create_apigw_cloudwatch_role(ctx)
    _swap_account_cw_role(ctx, cw_role_arn)

    lambda_role_arn = _create_lambda_execution_role(ctx)
    fn = _create_echo_lambda(ctx, lambda_role_arn)
    api = _create_rest_api_with_lambda_proxy(ctx, fn)
    stage_name = "prod"
    _deploy_stage(ctx, api["id"], stage_name)

    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    access_log_group = ctx.unique_name("/sim2real/apigw-access-")
    logs.create_log_group(logGroupName=access_log_group, tags=_resource_tags())
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=access_log_group))
    log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{access_log_group}"

    apigw = ctx.client("apigateway")

    # broken condition: format has neither $context.requestId nor $context.extendedRequestId.
    bad_format = '{"httpMethod":"$context.httpMethod","status":"$context.status"}'
    try:
        apigw.update_stage(
            restApiId=api["id"],
            stageName=stage_name,
            patchOperations=[
                {"op": "replace", "path": "/accessLogSettings/destinationArn", "value": log_group_arn},
                {"op": "replace", "path": "/accessLogSettings/format", "value": bad_format},
            ],
        )
        raised = False
        error_message = ""
    except apigw.exceptions.BadRequestException as exc:
        raised = True
        error_message = exc.response.get("Error", {}).get("Message", "")
    assert raised, (
        "expected UpdateStage to reject an access log format without "
        "$context.requestId/$context.extendedRequestId"
    )
    expected_message = (
        "Access Log format must include either $context.requestId or "
        f"$context.extendedRequestId : '{bad_format}'"
    )
    assert error_message == expected_message, (
        "expected the BadRequestException to name both $context.requestId and "
        f"$context.extendedRequestId, got message: {error_message!r}"
    )

    # positive control: fix the ONE broken condition (add requestId back), same destination log
    # group, and observe the identical UpdateStage call succeed and logs actually flow.
    good_format = (
        '{"requestId":"$context.requestId","httpMethod":"$context.httpMethod",'
        '"status":"$context.status"}'
    )
    apigw.update_stage(
        restApiId=api["id"],
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/accessLogSettings/destinationArn", "value": log_group_arn},
            {"op": "replace", "path": "/accessLogSettings/format", "value": good_format},
        ],
    )
    url = f"{ctx.rest_api_url(api['id'], stage_name)}/echo"
    status, _ = _wait_for_200(url, timeout_s=60)
    assert status == 200, f"expected the echo route to answer 200 after the format fix, got {status}"
    events = _poll_log_events_with_traffic(ctx, access_log_group, url, timeout_s=220, min_events=1)
    assert len(events) > 0, "positive control: access logs never delivered after fixing the format"


_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true"}


def _resource_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


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
        Tags=_resource_tags_kv(),
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
        RoleName=name,
        AssumeRolePolicyDocument=_trust_policy("lambda.amazonaws.com"),
        Tags=_resource_tags_kv(),
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
                Tags=_resource_tags(),
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
        name=ctx.unique_name("sim2real-api-"), tags=_resource_tags()
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


def _set_access_logging(ctx, api_id: str, stage_name: str, destination_arn: str, fmt: str) -> None:
    apigw = ctx.client("apigateway")
    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/accessLogSettings/destinationArn", "value": destination_arn},
            {"op": "replace", "path": "/accessLogSettings/format", "value": fmt},
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



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
