"""apigw-access-log-group-created-per-stage."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags

CHECK = "apigw-access-log-group-created-per-stage"
GROUP = "log-delivery"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:endpoint", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """Two stages of the SAME REST API, each with its own accessLogSettings destination, write
    access-log entries ONLY to their own dedicated log group — traffic to stage A never leaks
    into stage B's log group and vice versa."""
    cw_role_arn = _create_apigw_cloudwatch_role(ctx)
    _swap_account_cw_role(ctx, cw_role_arn)

    lambda_role_arn = _create_lambda_execution_role(ctx)
    fn = _create_echo_lambda(ctx, lambda_role_arn)
    api = _create_rest_api_with_lambda_proxy(ctx, fn)

    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    log_format = '{"requestId":"$context.requestId","stage":"$context.stage"}'

    stages = {}
    for stage_name in ("stagea", "stageb"):
        _deploy_stage(ctx, api["id"], stage_name)
        group_name = ctx.unique_name(f"/sim2real/apigw-{stage_name}-")
        logs.create_log_group(logGroupName=group_name, tags={"sim2real:managed": "true"})
        ctx.on_cleanup(lambda g=group_name: logs.delete_log_group(logGroupName=g))
        group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{group_name}"
        _set_access_logging(ctx, api["id"], stage_name, group_arn, log_format)
        stages[stage_name] = {"log_group": group_name}

    url_a = f"{ctx.rest_api_url(api['id'], 'stagea')}/echo"
    start_ms = int(time.time() * 1000)
    for _ in range(5):
        status, _ = _wait_for_200(url_a, timeout_s=60)
        assert status == 200, f"expected GET {url_a} to return 200, got {status}"

    poll_start = time.monotonic()
    events_a = _poll_log_events(
        ctx, stages["stagea"]["log_group"], start_ms, timeout_s=180, min_events=1, traffic_url=url_a
    )
    assert len(events_a) > 0, "stage A traffic never reached stage A's dedicated log group"
    delivery_latency_s = time.monotonic() - poll_start
    for e in events_a:
        parsed = json.loads(e["message"])
        assert parsed["stage"] == "stagea", f"expected stage A's log group to carry stage=stagea, got {parsed}"

    # Absence is bounded by the delivery latency measured above on the same wiring (same account,
    # same API, same access-log pipeline), not by a fixed guess — a leak arriving after a too-short
    # window would otherwise read as isolation.
    absence_window_s = max(3 * delivery_latency_s, 15.0)
    events_b = _poll_log_events(
        ctx, stages["stageb"]["log_group"], start_ms, timeout_s=absence_window_s, min_events=1
    )
    assert len(events_b) == 0, f"stage A traffic leaked into stage B's log group: {events_b}"

    # Second independent observable: stage B's log group must not even have opened a log stream,
    # not merely have zero events visible through the (separately implementable) filter API.
    streams_b = logs.describe_log_streams(logGroupName=stages["stageb"]["log_group"])["logStreams"]
    assert not streams_b, f"stage B's log group opened a log stream despite no traffic: {streams_b}"


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
                Tags={"sim2real:managed": "true"},
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
    ctx,
    log_group_name: str,
    start_time_ms: int,
    timeout_s: float = 180,
    min_events: int = 1,
    traffic_url: str | None = None,
) -> list:
    # traffic_url keeps requests flowing while polling, so delivery does not hinge on one burst
    # sent right after the stage's accessLogSettings change.
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    events: list = []
    while time.monotonic() < deadline:
        if traffic_url:
            _wait_for_200(traffic_url, timeout_s=30)
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
