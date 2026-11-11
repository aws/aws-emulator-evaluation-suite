"""obs-apigateway-2-execution-log-level-and-data-trace-gate-delivered-lines."""
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

CHECK = "obs-apigateway-2-execution-log-level-and-data-trace-gate-delivered-lines"
GROUP = "log-delivery"
SERVICES = ["apigateway", "lambda", "logs"]

_STAGES = ("off", "err", "info", "trace")
_COMPLETED_200 = "Method completed with status: 200"
_BODY_LINE = "Method request body before transformations"
_MALFORMED = "Execution failed due to configuration error: Malformed Lambda proxy response"


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:endpoint",
    "plane:data", "resource:account-singleton:apigateway-account",
)
def run(ctx) -> None:
    """A stage's execution-log settings decide which lines reach the execution log group, which only
    exists once logging is on: OFF writes nothing, ERROR logs a malformed proxy response but no 200,
    INFO logs completions, and only dataTrace logs the request body (and stops when toggled off)."""
    t_start_ms = int(time.time() * 1000)
    apigw = ctx.client("apigateway")
    lam = ctx.client("lambda")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    fn_name = ctx.unique_name("sim2real-xsvc-obsfn-")
    state = {"api_id": None, "fn": fn_name}
    # Registered FIRST so LIFO runs it LAST, after the API and function are gone. It reaps the
    # four execution-log groups and /aws/lambda/<fn>, all created by the services, not by us.
    ctx.on_cleanup(lambda: _reap_log_groups(ctx, state))

    cw_role_arn = _create_role(
        ctx, "apigateway.amazonaws.com",
        "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs", "obsagcw",
    )
    fn_role_arn = _create_role(
        ctx, "lambda.amazonaws.com",
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole", "obsfnrole",
    )
    fn_arn = _create_function(ctx, fn_name, fn_role_arn)

    # Account-global prerequisite (MEASURED: without it, enabling logging is refused with
    # BadRequestException "CloudWatch Logs role ARN must be set in account settings").
    _install_account_cloudwatch_role(ctx, cw_role_arn)

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-xsvc-obsapi-"),
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
    lam.add_permission(
        FunctionName=fn_name, StatementId="apigw-invoke", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*",
    )
    dep_id = apigw.create_deployment(restApiId=api_id)["id"]
    for st in _STAGES:
        apigw.create_stage(restApiId=api_id, stageName=st, deploymentId=dep_id)

    groups = {st: f"API-Gateway-Execution-Logs_{api_id}/{st}" for st in _STAGES}

    # --- the group does not exist while no stage has logging enabled ------------------
    for st in _STAGES:
        assert _describe_group(ctx, groups[st]) is None, (
            f"execution log group {groups[st]!r} exists before logging was ever enabled on "
            f"stage {st!r}; it must not be created by stage creation or the account role"
        )

    # --- toggle the settings with UpdateStage patch operations -------------------------
    _patch_stage(ctx, api_id, "off", [("/*/*/logging/loglevel", "OFF")])
    _patch_stage(ctx, api_id, "err", [("/*/*/logging/loglevel", "ERROR"),
                                      ("/*/*/logging/dataTrace", "false")])
    _patch_stage(ctx, api_id, "info", [("/*/*/logging/loglevel", "INFO"),
                                       ("/*/*/logging/dataTrace", "false")])
    _patch_stage(ctx, api_id, "trace", [("/*/*/logging/loglevel", "INFO"),
                                        ("/*/*/logging/dataTrace", "true")])
    expect = {"off": ("OFF", False), "err": ("ERROR", False), "info": ("INFO", False),
              "trace": ("INFO", True)}
    for st, (lvl, dt) in expect.items():
        ms = apigw.get_stage(restApiId=api_id, stageName=st).get("methodSettings", {}).get("*/*", {})
        assert (ms.get("loggingLevel"), ms.get("dataTraceEnabled")) == (lvl, dt), (
            f"stage {st!r} methodSettings['*/*'] should read loggingLevel={lvl!r} "
            f"dataTraceEnabled={dt!r} after UpdateStage, got {ms!r}"
        )

    # --- enabling (not traffic) creates the group, with no retention --------------------
    # Not one request has been sent to any stage yet.
    for st in ("err", "info", "trace"):
        g = _poll(lambda st=st: _describe_group(ctx, groups[st]), lambda g: g is not None,
                  timeout_s=30, interval_s=2,
                  what=f"execution log group {groups[st]!r} to exist after enabling logging "
                       f"(before any request)")
        assert "retentionInDays" not in g, (
            f"API Gateway must create {groups[st]!r} with no retention policy (never expire); "
            f"got retentionInDays={g.get('retentionInDays')!r}"
        )
    assert _describe_group(ctx, groups["off"]) is None, (
        f"{groups['off']!r} was created by a loglevel=OFF patch; only ERROR/INFO create it"
    )

    # --- drive traffic through all four stages and observe ------------------------------
    urls = {st: _invoke_url(ctx, api_id, st, "echo") for st in _STAGES}
    sent: list[dict] = []        # every request: stage, kind, rid, ts, marker, phase
    first_seen: dict = {}        # rid -> wall time its first line was observed
    latencies: list[float] = []  # presence latencies (request sent -> its line observed)
    goals = {"err_ok_sandwich": None, "info_completed": None, "trace_marker": None,
             "trace_off": None}
    toggle_ts = None
    t_enable = time.time()
    traffic_deadline = t_enable + 210

    def send(st, kind, body_marker=None):
        if body_marker is not None:
            status, rid = _http(urls[st] + "?mode=ok", json.dumps({"marker": body_marker}))
        else:
            status, rid = _http(urls[st] + f"?mode={kind}", None)
        want = 502 if kind == "bad" else 200
        assert status == want, (
            f"{kind!r} request to stage {st!r} returned HTTP {status}, expected {want} "
            f"(a malformed Lambda proxy response must surface as 502)"
        )
        assert rid, f"response from stage {st!r} carried no x-amzn-RequestId header"
        rec = {"stage": st, "kind": kind, "rid": rid, "ts": time.time(), "marker": body_marker,
               "phase": "after-toggle" if toggle_ts else "before-toggle"}
        sent.append(rec)
        return rec

    while not all(goals.values()):
        if time.time() > traffic_deadline:
            raise AssertionError(
                f"timed out after {traffic_deadline - t_enable:.0f}s waiting for execution-log "
                f"evidence; unmet goals: {[k for k, v in goals.items() if not v]!r}; "
                f"presence latencies measured so far: {latencies!r}"
            )
        send("off", "ok")
        send("err", "ok")
        send("err", "bad")
        send("info", "ok", body_marker="INFO" + uuid.uuid4().hex)
        send("trace", "ok", body_marker="TRACE" + uuid.uuid4().hex)
        time.sleep(4)

        assert _describe_group(ctx, groups["off"]) is None, (
            f"{groups['off']!r} appeared although stage 'off' never enabled logging "
            f"({sum(1 for r in sent if r['stage'] == 'off')} requests served)"
        )
        lines = {st: _lines(ctx, groups[st], t_start_ms) for st in ("err", "info", "trace")}
        now = time.time()
        for rec in sent:
            if rec["rid"] in first_seen:
                continue
            if any(m.startswith(f"({rec['rid']})") for m in lines.get(rec["stage"], [])):
                first_seen[rec["rid"]] = now
                latencies.append(now - rec["ts"])

        # err: an ok request with a LOGGED bad request on each side of it. The bad request
        # before proves ERROR was in effect when the ok one was served; the one after is the
        # delivery barrier.
        if not goals["err_ok_sandwich"]:
            errs = [r for r in sent if r["stage"] == "err"]
            for i, r in enumerate(errs):
                if r["kind"] != "ok":
                    continue
                before = [b for b in errs[:i] if b["kind"] == "bad" and b["rid"] in first_seen]
                after = [b for b in errs[i + 1:] if b["kind"] == "bad" and b["rid"] in first_seen]
                if before and after:
                    goals["err_ok_sandwich"] = r
                    break
        if not goals["info_completed"]:
            for r in sent:
                if r["stage"] == "info" and any(
                    m.startswith(f"({r['rid']})") and _COMPLETED_200 in m for m in lines["info"]
                ):
                    goals["info_completed"] = r
                    break
        if not goals["trace_marker"]:
            for r in sent:
                if r["stage"] == "trace" and any(
                    m.startswith(f"({r['rid']})") and _BODY_LINE in m and r["marker"] in m
                    for m in lines["trace"]
                ):
                    goals["trace_marker"] = r
                    # The toggle: dataTrace true -> false on the SAME stage.
                    _patch_stage(ctx, api_id, "trace", [("/*/*/logging/dataTrace", "false")])
                    toggle_ts = time.time()
                    ms = apigw.get_stage(restApiId=api_id, stageName="trace")["methodSettings"]["*/*"]
                    assert ms.get("dataTraceEnabled") is False, (
                        f"dataTrace=false patch not reflected by GetStage: {ms!r}"
                    )
                    break
        elif not goals["trace_off"]:
            # First request served after the toggle whose completion is logged and whose
            # marker is not. Settings propagate in ~30-45s, so earlier requests may still
            # carry their body; convergence is bounded by traffic_deadline.
            for r in sent:
                if r["stage"] != "trace" or r["phase"] != "after-toggle":
                    continue
                mine = [m for m in lines["trace"] if m.startswith(f"({r['rid']})")]
                if any(_COMPLETED_200 in m for m in mine) and not any(r["marker"] in m for m in mine):
                    goals["trace_off"] = r
                    break

    # --- hold every absence for >= 2x the measured presence latency ----------------------
    assert latencies, "no presence latency was ever measured"
    presence_latency = max(latencies)
    hold_s = max(2 * presence_latency, 10.0)
    last_ts = max(r["ts"] for r in sent)
    hold_until = last_ts + hold_s
    print(f"[{CHECK}] presence latency max={presence_latency:.1f}s samples={len(latencies)} "
          f"hold={hold_s:.1f}s after last request", file=sys.stderr)
    while True:
        assert _describe_group(ctx, groups["off"]) is None, (
            f"{groups['off']!r} appeared during the hold window although logging is OFF"
        )
        if time.time() >= hold_until:
            break
        time.sleep(5)
    lines = {st: _lines(ctx, groups[st], t_start_ms) for st in ("err", "info", "trace")}

    # err: the malformed proxy response is logged at ERROR ...
    bad_logged = [r for r in sent if r["stage"] == "err" and r["kind"] == "bad" and r["rid"] in first_seen]
    assert bad_logged, "no 502 request on the ERROR stage was ever logged"
    for r in bad_logged:
        mine = [m for m in lines["err"] if m.startswith(f"({r['rid']})")]
        assert any(_MALFORMED in m for m in mine), (
            f"ERROR-level lines for 502 request {r['rid']} lack {_MALFORMED!r}: {mine!r}"
        )
    # ... and the successful request in between logged nothing at all.
    ok = goals["err_ok_sandwich"]
    ok_lines = [m for m in lines["err"] if ok["rid"] in m]
    assert not ok_lines, (
        f"loglevel=ERROR must log nothing for a successful request, but request {ok['rid']} "
        f"logged {ok_lines!r} (held {time.time() - ok['ts']:.0f}s after it was sent)"
    )
    completed_at_error = [m for m in lines["err"] if "Method completed" in m]
    assert not completed_at_error, (
        f"loglevel=ERROR must never log 'Method completed', got {completed_at_error[:3]!r}"
    )

    # info: completion is logged, but no request body ever is (dataTrace never enabled).
    i = goals["info_completed"]
    assert any(m.startswith(f"({i['rid']})") and _COMPLETED_200 in m for m in lines["info"])
    info_bodies = [m for m in lines["info"] if _BODY_LINE in m]
    assert not info_bodies, (
        f"loglevel=INFO with dataTrace=false must not log request bodies, got {info_bodies[:3]!r}"
    )
    leaked = [r["marker"] for r in sent if r["stage"] == "info"
              if any(r["marker"] in m for m in lines["info"])]
    assert not leaked, f"dataTrace=false stage leaked body markers into its log: {leaked[:3]!r}"

    # trace: the marker was logged under dataTrace=true, and is absent after the toggle.
    t = goals["trace_marker"]
    body_lines = [m for m in lines["trace"] if m.startswith(f"({t['rid']})") and _BODY_LINE in m]
    assert body_lines and t["marker"] in body_lines[0], (
        f"dataTrace=true must log '{_BODY_LINE}: <body>' with the marker {t['marker']!r}; "
        f"got {body_lines!r}"
    )
    off = goals["trace_off"]
    off_lines = [m for m in lines["trace"] if m.startswith(f"({off['rid']})")]
    assert any(_COMPLETED_200 in m for m in off_lines), off_lines
    assert not any(off["marker"] in m or _BODY_LINE in m for m in off_lines), (
        f"after toggling dataTrace to false, request {off['rid']} still logged its body: "
        f"{off_lines!r}"
    )
    print(f"[{CHECK}] trace toggle converged {off['ts'] - toggle_ts:.1f}s after the patch; "
          f"{len(sent)} requests total", file=sys.stderr)


# ===== helpers (self-contained) =====

_FN_CODE = (
    "import json\n"
    "def handler(event, context):\n"
    "    q = event.get('queryStringParameters') or {}\n"
    "    if q.get('mode') == 'bad':\n"
    "        return 'not-a-lambda-proxy-response'\n"
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
