"""apigw-access-logs-custom-format."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags

CHECK = "apigw-access-logs-custom-format"
GROUP = "data-format"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "dp:endpoint", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """A custom JSON access-log format built from $context variables renders the correct,
    per-request field values (requestId, httpMethod, resourcePath, status) in the delivered
    CloudWatch log entries."""
    cw_role_arn = _create_apigw_cloudwatch_role(ctx)
    _swap_account_cw_role(ctx, cw_role_arn)

    lambda_role_arn = _create_lambda_execution_role(ctx)
    fn = _create_echo_lambda(ctx, lambda_role_arn)
    api = _create_rest_api_with_lambda_proxy(ctx, fn)
    stage_name = "prod"
    _deploy_stage(ctx, api["id"], stage_name)

    logs = ctx.client("logs")
    access_log_group = ctx.unique_name("/sim2real/apigw-access-")
    logs.create_log_group(logGroupName=access_log_group, tags=dict(_MGMT_TAGS))
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=access_log_group))
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{access_log_group}"

    log_format = json.dumps(
        {
            "requestId": "$context.requestId",
            "httpMethod": "$context.httpMethod",
            "resourcePath": "$context.resourcePath",
            "status": "$context.status",
        }
    )
    apigw = ctx.client("apigateway")
    apigw.update_stage(
        restApiId=api["id"],
        stageName=stage_name,
        patchOperations=[
            {"op": "replace", "path": "/accessLogSettings/destinationArn", "value": log_group_arn},
            {"op": "replace", "path": "/accessLogSettings/format", "value": log_format},
        ],
    )

    url = f"{ctx.rest_api_url(api['id'], stage_name)}/echo"
    status, _, request_id = _wait_for_200(url, timeout_s=60)
    assert status == 200
    assert request_id, "GET response carried no x-amzn-RequestId header to correlate against"
    driven_request_ids = {request_id}

    # First-time activation of the account CloudWatch role can lag well behind update_account /
    # update_stage returning success, so keep re-driving traffic while polling for delivery.
    events = _poll_log_events_with_traffic(
        ctx, access_log_group, url, driven_request_ids, timeout_s=230, min_events=1
    )
    assert len(events) > 0, f"no access-log entries delivered to {access_log_group}"
    parsed = [json.loads(e["message"]) for e in events]
    # requestId must be one of the ids AWS actually handed back for a request we sent, not
    # merely "not the literal $context.requestId text" -- that would pass a target that
    # substitutes a bogus but non-placeholder string too.
    match = next((p for p in parsed if p.get("requestId") in driven_request_ids), None)
    assert match is not None, (
        f"no delivered access-log entry's requestId matched a request this check actually sent "
        f"({sorted(driven_request_ids)}); parsed entries={parsed}"
    )
    assert match["httpMethod"] == "GET"
    assert match["resourcePath"] == "/echo"
    assert match["status"] == "200"


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


_MGMT_TAGS = {"sim2real:managed": "true"}


def _create_apigw_cloudwatch_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-apigwcw-")
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust_policy("apigateway.amazonaws.com"),
        Tags=[{"Key": k, "Value": v} for k, v in _MGMT_TAGS.items()],
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
        Tags=[{"Key": k, "Value": v} for k, v in _MGMT_TAGS.items()],
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
                Tags=dict(_MGMT_TAGS),
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
        name=ctx.unique_name("sim2real-api-"), tags=dict(_MGMT_TAGS)
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


def _wait_for_200(url: str, timeout_s: float = 180) -> tuple[int, bytes, str | None]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read(), resp.headers.get("x-amzn-RequestId")
        except urllib.error.HTTPError as exc:
            last = (exc.code, exc.read())
            if exc.code == 200:
                return exc.code, last[1], exc.headers.get("x-amzn-RequestId")
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
    ctx,
    log_group_name: str,
    url: str,
    driven_request_ids: set,
    timeout_s: float = 230,
    min_events: int = 1,
) -> list:
    """Polls for delivered log events while periodically re-driving traffic through the stage.
    First-time activation of the account CloudWatch role can lag well behind the update_account
    call succeeding, so a single early request may predate the moment delivery actually starts;
    keep refreshing the marker request so we always have something recent in-flight to observe.
    Each refreshed request's x-amzn-RequestId is recorded into driven_request_ids so the caller
    can correlate a delivered log entry against a request it actually sent."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    start_time_ms = int(time.time() * 1000)
    events: list = []
    last_request = 0.0
    while time.monotonic() < deadline:
        if time.monotonic() - last_request > 20:
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    rid = resp.headers.get("x-amzn-RequestId")
                    if rid:
                        driven_request_ids.add(rid)
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
