"""apigw-method-level-log-level-overrides-the-stage-wide-level."""
from __future__ import annotations

import io
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-method-level-log-level-overrides-the-stage-wide-level"
GROUP = "log-delivery"
SERVICES = ["apigateway", "lambda", "logs"]

_STAGES = ("s",)
_COMPLETED_200 = "Method completed with status: 200"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:endpoint",
    "plane:data", "resource:account-singleton:apigateway-account",
)
def run(ctx) -> None:
    """A method-level INFO logging override beats the stage-wide ERROR level: successful POSTs log their
    INFO trace while successful GETs on the same resource log nothing."""
    t_start_ms = int(time.time() * 1000)
    apigw = ctx.client("apigateway")
    lam = ctx.client("lambda")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    fn_name = ctx.unique_name("sim2real-xsvc-mlvlfn-")
    state = {"api_id": None, "fn": fn_name}
    ctx.on_cleanup(lambda: _reap_log_groups(ctx, state))  # runs LAST (LIFO)

    cw_role_arn = _create_role(
        ctx, "apigateway.amazonaws.com",
        "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs", "mlvlagcw",
    )
    fn_role_arn = _create_role(
        ctx, "lambda.amazonaws.com",
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole", "mlvlfnrole",
    )
    fn_arn = _create_function(ctx, fn_name, fn_role_arn)
    _install_account_cloudwatch_role(ctx, cw_role_arn)

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-xsvc-mlvlapi-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    state["api_id"] = api_id
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    res_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="echo")["id"]
    for verb in ("GET", "POST"):
        apigw.put_method(restApiId=api_id, resourceId=res_id, httpMethod=verb,
                         authorizationType="NONE")
        apigw.put_integration(
            restApiId=api_id, resourceId=res_id, httpMethod=verb, type="AWS_PROXY",
            integrationHttpMethod="POST",
            uri=f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}/invocations",
        )
    lam.add_permission(
        FunctionName=fn_name, StatementId="apigw-invoke", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*",
    )
    dep_id = apigw.create_deployment(restApiId=api_id)["id"]
    apigw.create_stage(restApiId=api_id, stageName="s", deploymentId=dep_id)
    _patch_stage(ctx, api_id, "s", [("/*/*/logging/loglevel", "ERROR"),
                                    ("/~1echo/POST/logging/loglevel", "INFO")])
    ms = apigw.get_stage(restApiId=api_id, stageName="s").get("methodSettings", {})
    assert ms.get("*/*", {}).get("loggingLevel") == "ERROR", f"stage-wide level: {ms!r}"
    assert ms.get("~1echo/POST", {}).get("loggingLevel") == "INFO", (
        f"method-level override should be keyed '~1echo/POST' with loggingLevel INFO: {ms!r}"
    )
    assert "~1echo/GET" not in ms, f"no override was set for GET, yet GetStage shows one: {ms!r}"

    group = f"API-Gateway-Execution-Logs_{api_id}/s"
    url = _invoke_url(ctx, api_id, "s", "echo")
    sent: list[dict] = []
    first_seen: dict = {}
    latencies: list[float] = []
    judged = None
    t_loop = time.time()
    deadline = t_loop + 180
    while judged is None:
        if time.time() > deadline:
            raise AssertionError(
                f"no GET sandwiched between two logged POSTs within {deadline - t_loop:.0f}s; "
                f"the method-level INFO override never produced '{_COMPLETED_200}' for a POST "
                f"(latencies so far {latencies!r})"
            )
        for verb in ("GET", "POST"):
            mk = f"{verb}-{uuid.uuid4().hex}"
            body = json.dumps({"marker": mk}) if verb == "POST" else None
            status, rid = _http(f"{url}?marker={mk}", body)
            assert status == 200, f"{verb} /echo returned {status}, expected 200"
            assert rid, f"{verb} response carried no x-amzn-RequestId header"
            sent.append({"verb": verb, "rid": rid, "ts": time.time()})
        time.sleep(4)
        lines = _lines(ctx, group, t_start_ms)
        now = time.time()
        for r in sent:
            if r["rid"] not in first_seen and any(
                m.startswith(f"({r['rid']})") and _COMPLETED_200 in m for m in lines
            ):
                first_seen[r["rid"]] = now
                latencies.append(now - r["ts"])
        for i, r in enumerate(sent):
            if r["verb"] != "GET":
                continue
            before = [p for p in sent[:i] if p["verb"] == "POST" and p["rid"] in first_seen]
            after = [p for p in sent[i + 1:] if p["verb"] == "POST" and p["rid"] in first_seen]
            if before and after:
                judged = r
                break

    hold_s = max(2 * max(latencies), 10.0)
    hold_until = judged["ts"] + hold_s
    print(f"[{CHECK}] presence latency max={max(latencies):.1f}s hold={hold_s:.1f}s",
          file=sys.stderr)
    while time.time() < hold_until:
        time.sleep(3)
    lines = _lines(ctx, group, t_start_ms)

    post_ok = [p for p in sent if p["verb"] == "POST" and p["rid"] in first_seen]
    trace = [m for m in lines if m.startswith(f"({post_ok[0]['rid']})")]
    assert any("HTTP Method: POST, Resource Path: /echo" in m for m in trace), (
        f"INFO trace for the POST should name its method and resource: {trace!r}"
    )
    get_lines = [m for m in lines if judged["rid"] in m]
    assert not get_lines, (
        f"GET falls under the stage-wide ERROR level and succeeded, so it must log nothing; "
        f"request {judged['rid']} logged {get_lines!r}"
    )
    get_traces = [m for m in lines if "HTTP Method: GET" in m]
    assert not get_traces, f"no GET may be traced at INFO, got {get_traces[:3]!r}"


_FN_CODE = (
    "import json\n"
    "def handler(event, context):\n"
    "    return {'statusCode': 200, 'headers': {'Content-Type': 'application/json'},\n"
    "            'body': json.dumps({'ok': True})}\n"
)


def _poll(probe, done, *, timeout_s, interval_s, what):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last={last!r}")
        time.sleep(interval_s)


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _create_role(ctx, service: str, policy_arn: str, kind: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-xsvc-{kind}-")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return arn


def _create_function(ctx, name: str, role_arn: str) -> str:
    lam = ctx.client("lambda")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", _FN_CODE)
    deadline = time.monotonic() + 90
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": buf.getvalue()}, Timeout=10,
                Tags={"sim2real": CHECK},
            )["FunctionArn"]
            break
        except ClientError as exc:
            # IAM propagation: a brand-new role is not yet assumable by Lambda.
            if _code(exc) != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll(lambda: lam.get_function_configuration(FunctionName=name).get("State"),
          lambda s: s == "Active", timeout_s=90, interval_s=2, what=f"Lambda {name} Active")
    return arn


def _retry_throttled(fn, attempts=8):
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) != "TooManyRequestsException" or i == attempts - 1:
                raise
            time.sleep(2 * (i + 1))


def _install_account_cloudwatch_role(ctx, role_arn: str) -> None:
    """Point the account-global cloudwatchRoleArn at our role; restore the previous value.

    The restore writes exactly the value read here. Registered before the set (so a set that
    fails part-way is still undone) and after the role's own teardown, so LIFO restores BEFORE
    the role is deleted.
    """
    apigw = ctx.client("apigateway")
    original = apigw.get_account().get("cloudwatchRoleArn") or ""

    def _restore():
        _retry_throttled(lambda: apigw.update_account(patchOperations=[
            {"op": "replace", "path": "/cloudwatchRoleArn", "value": original}]))

    ctx.on_cleanup(_restore)
    deadline = time.monotonic() + 120
    while True:
        try:
            _retry_throttled(lambda: apigw.update_account(patchOperations=[
                {"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}]))
            break
        except ClientError as exc:
            # BadRequestException while IAM has not yet made the role assumable by API Gateway.
            if _code(exc) != "BadRequestException" or time.monotonic() > deadline:
                raise
            time.sleep(4)
    got = apigw.get_account().get("cloudwatchRoleArn")
    assert got == role_arn, f"GetAccount cloudwatchRoleArn is {got!r}, expected {role_arn!r}"


def _patch_stage(ctx, api_id: str, stage: str, ops) -> None:
    apigw = ctx.client("apigateway")
    _retry_throttled(lambda: apigw.update_stage(
        restApiId=api_id, stageName=stage,
        patchOperations=[{"op": "replace", "path": p, "value": v} for p, v in ops]))


def _describe_group(ctx, name: str):
    """The exact-named log group, or None. Prefix-filtered, so siblings cannot interfere."""
    logs = ctx.client("logs")
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        for g in page.get("logGroups", []):
            if g["logGroupName"] == name:
                return g
    return None


def _lines(ctx, group: str, start_ms: int) -> list:
    logs = ctx.client("logs")
    out = []
    try:
        for page in logs.get_paginator("filter_log_events").paginate(
            logGroupName=group, startTime=start_ms - 120_000
        ):
            out.extend(e.get("message", "") for e in page.get("events", []))
    except ClientError as exc:
        if _code(exc) != "ResourceNotFoundException":
            raise
    return out


def _invoke_url(ctx, api_id: str, stage: str, path: str) -> str:
    """The stage invoke URL from `ctx.rest_api_url`: the execute-api host on real AWS, else
    the `/_aws/execute-api/<id>/<stage>/` route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path}"


def _http(url: str, body):
    """One request; returns (status, x-amzn-RequestId). A 4xx/5xx is a result, not an error.
    Retries only connection-level failures (fresh execute-api DNS/TLS), bounded."""
    deadline = time.monotonic() + 60
    while True:
        req = urllib.request.Request(
            url, data=body.encode() if body is not None else None,
            method="POST" if body is not None else "GET",
            headers={"Content-Type": "application/json"} if body is not None else {},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                resp.read()
                return resp.status, resp.headers.get("x-amzn-RequestId")
        except urllib.error.HTTPError as exc:
            exc.read()
            return exc.code, exc.headers.get("x-amzn-RequestId")
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if time.monotonic() > deadline:
                raise AssertionError(f"{url} unreachable for 60s: {exc!r}") from exc
            time.sleep(3)


def _reap_log_groups(ctx, state) -> None:
    """Delete the service-created log groups, then re-check for an async writer recreating them.

    Both API Gateway (execution logs) and Lambda hold logs:CreateLogGroup and flush ~20s after
    a request, so one delete is one round, not a teardown. Bounded; a survivor raises, so the
    runner records it in cleanup_detail.
    """
    _leaks: list = []
    logs = ctx.client("logs")
    names = [f"/aws/lambda/{state['fn']}"]
    if state.get("api_id"):
        names += [f"API-Gateway-Execution-Logs_{state['api_id']}/{st}" for st in _STAGES]
    alive = names
    for _ in range(4):
        for n in alive:
            try:
                logs.delete_log_group(logGroupName=n)
            except ClientError as exc:
                if _code(exc) != "ResourceNotFoundException":
                    _leaks.append((f"delete_log_group {n}: {exc}", exc))
        time.sleep(12)
        alive = [n for n in names if _describe_group(ctx, n) is not None]
        if not alive:
            if _leaks:
                raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
                    (e for _, e in _leaks if e is not None), None
                )
            return
    _leaks.append((f"log groups recreated after 4 delete rounds: {alive!r}", None))
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
