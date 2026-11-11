"""apigw-stage-scoped-lambda-permission-other-stage-denied-and-logged."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-stage-scoped-lambda-permission-other-stage-denied-and-logged"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "lambda", "logs"]

_STAGES = ("allowed", "denied")
_INVALID_PERMS = "Execution failed due to configuration error: Invalid permissions on Lambda function"
_MARK = "SIM2REAL-MARK "


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data", "resource:account-singleton:apigateway-account",
)
def run(ctx) -> None:
    """A Lambda grant whose SourceArn names one stage lets only that stage invoke the function:
    another stage of the same deployment gets a 500, never invokes the function and logs the
    invalid-permissions cause at ERROR level; granting that stage repairs it."""
    t_start_ms = int(time.time() * 1000)
    apigw = ctx.client("apigateway")
    lam = ctx.client("lambda")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    fn_name = ctx.unique_name("sim2real-xsvc-scopefn-")
    state = {"api_id": None, "fn": fn_name}
    ctx.on_cleanup(lambda: _reap_log_groups(ctx, state))  # runs LAST (LIFO)

    cw_role_arn = _create_role(
        ctx, "apigateway.amazonaws.com",
        "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs", "scopeagcw",
    )
    fn_role_arn = _create_role(
        ctx, "lambda.amazonaws.com",
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole", "scopefnrole",
    )
    fn_arn = _create_function(ctx, fn_name, fn_role_arn)
    fn_log_group = f"/aws/lambda/{fn_name}"
    _install_account_cloudwatch_role(ctx, cw_role_arn)

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-xsvc-scopeapi-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    state["api_id"] = api_id
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    res_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="echo")["id"]
    apigw.put_method(restApiId=api_id, resourceId=res_id, httpMethod="ANY",
                     authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=res_id, httpMethod="ANY", type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}/invocations",
    )
    dep_id = apigw.create_deployment(restApiId=api_id)["id"]
    for st in _STAGES:
        apigw.create_stage(restApiId=api_id, stageName=st, deploymentId=dep_id)
        _retry_throttled(lambda st=st: apigw.update_stage(
            restApiId=api_id, stageName=st,
            patchOperations=[{"op": "replace", "path": "/*/*/logging/loglevel", "value": "ERROR"}]))

    scope = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}"
    lam.add_permission(
        FunctionName=fn_name, StatementId="allowed-stage-only", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com", SourceArn=f"{scope}/allowed/*/*",
    )
    policy = json.loads(lam.get_policy(FunctionName=fn_name)["Policy"])
    arns = [s["Condition"]["ArnLike"]["AWS:SourceArn"] for s in policy["Statement"]]
    assert arns == [f"{scope}/allowed/*/*"], f"resource policy SourceArn round-trip: {arns!r}"

    groups = {st: f"API-Gateway-Execution-Logs_{api_id}/{st}" for st in _STAGES}
    urls = {st: _invoke_url(ctx, api_id, st, "echo") for st in _STAGES}
    sent: list[dict] = []
    latencies: list[float] = []
    seen: set = set()
    first_allowed_200_ts = None
    barrier = None
    t_loop = time.time()
    deadline = t_loop + 180

    while barrier is None:
        if time.time() > deadline:
            raise AssertionError(
                f"no differential barrier within {deadline - t_loop:.0f}s: an 'allowed' marker "
                f"must reach {fn_log_group} AND a same-burst 'denied' request must be logged "
                f"with {_INVALID_PERMS!r}; latencies so far {latencies!r}"
            )
        burst = []
        for st in _STAGES:
            mk = f"{st}-{uuid.uuid4().hex}"
            t_send = time.time()
            status, rid, text = _http(f"{urls[st]}?marker={mk}")
            assert rid, f"response from stage {st!r} carried no x-amzn-RequestId header"
            rec = {"stage": st, "marker": mk, "rid": rid, "status": status, "ts": time.time(),
                   "t_send": t_send}
            sent.append(rec)
            burst.append(rec)
            if st == "denied":
                assert status == 500, (
                    f"stage 'denied' is outside the permission's SourceArn and must get 500, "
                    f"got {status}: {text[:300]!r}"
                )
                assert json.loads(text) == {"message": "Internal server error"}, (
                    f"denied-stage 500 body should be the gateway's own error, got {text[:300]!r}"
                )
            elif status == 200:
                first_allowed_200_ts = first_allowed_200_ts or rec["t_send"]
            else:
                # Positive control: a freshly added grant is allowed to take a moment, but
                # not forever, and once it has served a 200 it must keep doing so.
                assert first_allowed_200_ts is None and time.time() - t_loop < 60, (
                    f"stage 'allowed' is inside the SourceArn grant but returned {status}: "
                    f"{text[:300]!r}"
                )
        time.sleep(4)

        fn_msgs = _lines(ctx, fn_log_group, t_start_ms)
        denied_msgs = _lines(ctx, groups["denied"], t_start_ms)
        now = time.time()
        for r in sent:
            key = r["rid"]
            if key in seen:
                continue
            hit = (any(r["marker"] in m for m in fn_msgs) if r["stage"] == "allowed"
                   else any(m.startswith(f"({r['rid']})") for m in denied_msgs))
            if hit:
                seen.add(key)
                latencies.append(now - r["ts"])
        for r in sent:
            if r["stage"] != "denied" or r["rid"] not in seen:
                continue
            twin = next((a for a in sent if a["stage"] == "allowed" and a["status"] == 200
                         and abs(a["ts"] - r["ts"]) < 5 and a["rid"] in seen), None)
            if twin:
                barrier = (twin, r)
                break

    # Barrier: an allowed marker sent after the last denied request reaches the function log.
    after = f"allowed-{uuid.uuid4().hex}"
    status, _, text = _http(f"{urls['allowed']}?marker={after}")
    assert status == 200, (
        f"stage 'allowed' returned {status} to the trailing control: {text[:300]!r}")
    left = ctx.time_left()
    _poll(lambda: any(after in m for m in _lines(ctx, fn_log_group, t_start_ms)), bool,
          timeout_s=90 if left is None else max(1.0, min(90, left - 5.0)), interval_s=2,
          what=f"trailing allowed marker {after!r} to reach {fn_log_group}")
    _assert_no_denied_marker(ctx, fn_log_group, sent, t_start_ms)

    denied_lines = _lines(ctx, groups["denied"], t_start_ms)
    twin, d = barrier
    d_lines = [m for m in denied_lines if m.startswith(f"({d['rid']})")]
    assert any(_INVALID_PERMS in m for m in d_lines), (
        f"ERROR log for denied request {d['rid']} should state {_INVALID_PERMS!r}: {d_lines!r}"
    )
    allowed_lines = _lines(ctx, groups["allowed"], t_start_ms)
    ok_rids = {r["rid"] for r in sent if r["stage"] == "allowed" and r["status"] == 200}
    wrong = [m for m in allowed_lines if _INVALID_PERMS in m and m[1:37] in ok_rids]
    assert not wrong, f"a 200 on the allowed stage was logged as a permission failure: {wrong!r}"
    fn_group = _describe_group(ctx, fn_log_group)
    assert fn_group is not None, f"{fn_log_group} never appeared although 'allowed' got 200s"
    # first_allowed_200_ts is when that request was SENT; the group is created mid-request.
    assert fn_group["creationTime"] >= int(first_allowed_200_ts * 1000) - 2_000, (
        f"{fn_log_group} was created at {fn_group['creationTime']} ms, before the first allowed "
        f"200 at {int(first_allowed_200_ts * 1000)} ms: the function ran for a denied request"
    )

    # Repair exactly the one broken thing and require the SAME stage to reach the function.
    lam.add_permission(
        FunctionName=fn_name, StatementId="denied-stage-repair", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com", SourceArn=f"{scope}/denied/*/*",
    )
    mk = f"repaired-{uuid.uuid4().hex}"
    repair_deadline = time.time() + 90
    while True:
        status, _, text = _http(f"{urls['denied']}?marker={mk}")
        if status == 200:
            break
        assert status == 500 and time.time() < repair_deadline, (
            f"after granting stage 'denied' it should serve 200; last {status}: {text[:300]!r}"
        )
        time.sleep(3)
    _poll(lambda: any(mk in m for m in _lines(ctx, fn_log_group, t_start_ms)), bool,
          timeout_s=90, interval_s=4,
          what=f"repaired-stage marker {mk!r} to reach {fn_log_group}")


# ===== helpers =====

_FN_CODE = (
    "import json\n"
    "def handler(event, context):\n"
    "    q = event.get('queryStringParameters') or {}\n"
    "    print('" + _MARK + "' + str(q.get('marker')))\n"
    "    return {'statusCode': 200, 'headers': {'Content-Type': 'application/json'},\n"
    "            'body': json.dumps({'ok': True})}\n"
)


def _assert_no_denied_marker(ctx, fn_log_group, sent, start_ms):
    msgs = _lines(ctx, fn_log_group, start_ms)
    reached = [r["marker"] for r in sent if r["status"] != 200
               if any(r["marker"] in m for m in msgs)]
    assert not reached, (
        f"requests refused with 500 still invoked the function; markers in its log: {reached!r}"
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
    """Point the account-global cloudwatchRoleArn at our role; restore exactly the previous
    value on cleanup. LIFO restores it before the role is deleted."""
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


def _describe_group(ctx, name: str):
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


def _http(url: str):
    """One GET; returns (status, x-amzn-RequestId, body). A 4xx/5xx is a result, not an error.
    Retries only connection-level failures (fresh execute-api DNS/TLS), bounded."""
    deadline = time.monotonic() + 60
    while True:
        try:
            with urllib.request.urlopen(urllib.request.Request(url), timeout=20) as resp:
                return resp.status, resp.headers.get("x-amzn-RequestId"), resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers.get("x-amzn-RequestId"), exc.read().decode()
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if time.monotonic() > deadline:
                raise AssertionError(f"{url} unreachable for 60s: {exc!r}") from exc
            time.sleep(3)


def _reap_log_groups(ctx, state) -> None:
    """Delete the service-created log groups, then re-check for an async writer recreating
    them (API Gateway and Lambda both flush after the request returned). Bounded; a survivor
    raises."""
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
