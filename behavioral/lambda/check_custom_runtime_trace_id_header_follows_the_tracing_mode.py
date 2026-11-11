"""custom-runtime-trace-id-header-follows-the-tracing-mode."""

from __future__ import annotations

import base64
import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "custom-runtime-trace-id-header-follows-the-tracing-mode"
GROUP = 'data-plane'
SERVICES = ['lambda']

BOOTSTRAP = r'''#!/bin/sh
API="http://$AWS_LAMBDA_RUNTIME_API/2018-06-01/runtime/invocation"
while true; do
  curl -sS -D /tmp/h -o /tmp/e "$API/next"
  RID=$(grep -i '^lambda-runtime-aws-request-id:' /tmp/h | tr -d '\r' | sed 's/^[^:]*: *//')
  TID=$(grep -i '^lambda-runtime-trace-id:' /tmp/h | tr -d '\r' | sed 's/^[^:]*: *//')
  printf '{"trace":"%s","rid":"%s"}' "$TID" "$RID" > /tmp/r
  curl -sS -o /dev/null -X POST --data-binary @/tmp/r "$API/$RID/response"
done
'''

_ROOT = re.compile(r"1-[0-9a-f]{8}-[0-9a-f]{24}")
_PARENT = re.compile(r"[0-9a-f]{16}")

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _teardown(undo, *not_found):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_groups(logs, names, *, reads=3, interval_s=4.0, budget_s=40.0):
    """Delete every group in ``names`` until ``reads`` consecutive rounds find all absent.

    A log stream an invocation buffered can flush after the function is deleted and recreate its
    group, so one delete is one round, not a teardown. Raises if a group is still coming back.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        present = [
            name for name in names
            if any(g["logGroupName"] == name
                   for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"])
        ]
        for name in present:
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        absent = 0 if present else absent + 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log groups {present!r} still present after {budget_s}s")
            time.sleep(interval_s)


_LOG_GROUPS: list = []


def _log_groups(ctx):
    """This run's /aws/lambda group names; one reap, registered before the first function, covers all."""
    for owner, names in _LOG_GROUPS:
        if owner is ctx:
            return names
    names: list = []
    _LOG_GROUPS.append((ctx, names))
    logs = ctx.client("logs")
    # Registered BEFORE any create, so LIFO runs it after every function has been deleted.
    ctx.on_cleanup(lambda: _reap_log_groups(logs, names))
    return names


def _make_zip(entries):
    """A deployment zip with an explicit unix mode on every member."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            zf.writestr(info, data)
    return buf.getvalue()


def _execution_role(ctx):
    """An execution role this check creates and deletes."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-l3-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_TRUST,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC), "NoSuchEntity"))
    return arn


def _function(ctx, lam, role, label, zipbytes, *, runtime, handler, **extra):
    """Create a function, register its teardown and log-group reap, and wait for State=Active."""
    name = ctx.unique_name(f"sim2real-l3-{label}-")
    _log_groups(ctx).append(f"/aws/lambda/{name}")
    kwargs = dict(FunctionName=name, Runtime=runtime, Handler=handler, Role=role,
                  Code={"ZipFile": zipbytes}, MemorySize=256, Timeout=15,
                  Tags={"sim2real": CHECK})
    kwargs.update(extra)
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            # IAM propagation of the role created above exposes no condition to poll.
            if (err["Code"] != "InvalidParameterValueException"
                    or err["Message"] != _ROLE_NOT_READY or time.monotonic() > deadline):
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _wait_settled(lam, name)
    return name


def _wait_settled(lam, name, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        assert cfg["State"] != "Failed", f"{name} entered State=Failed: {cfg.get('StateReason')!r}"
        if cfg["State"] == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        assert time.monotonic() < deadline, (
            f"{name} did not settle within {timeout_s}s: State={cfg['State']!r} "
            f"LastUpdateStatus={cfg.get('LastUpdateStatus')!r}")
        time.sleep(1)


def _invoke(lam, name, payload, **extra):
    """Invoke synchronously with the log tail; ``payload`` is raw bytes or a JSON-able value."""
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    before_ms = time.time() * 1000.0
    resp = lam.invoke(FunctionName=name, Payload=body, LogType="Tail", **extra)
    after_ms = time.time() * 1000.0
    return {
        "status": resp["StatusCode"],
        "function_error": resp.get("FunctionError"),
        "raw": resp["Payload"].read(),
        "content_type": resp["ResponseMetadata"]["HTTPHeaders"].get("content-type"),
        "request_id": resp["ResponseMetadata"]["RequestId"],
        "log": base64.b64decode(resp.get("LogResult", "")).decode("utf-8", "replace"),
        "before_ms": before_ms,
        "after_ms": after_ms,
    }


def _ok(name, r):
    """The JSON body of a successful invoke; fails naming the error otherwise."""
    assert r["status"] == 200, f"{name}: StatusCode {r['status']!r}, payload {r['raw']!r}"
    assert r["function_error"] is None, (
        f"{name}: FunctionError={r['function_error']!r}, payload {r['raw'][:600]!r}")
    return json.loads(r["raw"])


def _failed(name, r):
    """The JSON error document of an invoke that must report FunctionError=Unhandled."""
    assert r["status"] == 200, f"{name}: StatusCode {r['status']!r}, payload {r['raw']!r}"
    assert r["function_error"] == "Unhandled", (
        f"{name}: FunctionError={r['function_error']!r} (expected 'Unhandled'), "
        f"payload {r['raw'][:600]!r}")
    return json.loads(r["raw"])


def _fields(header):
    """``Root=..;Parent=..;Sampled=..`` as a dict."""
    out = {}
    for part in header.split(";"):
        key, sep, value = part.partition("=")
        assert sep, f"trace header segment {part!r} of {header!r} is not key=value"
        out[key] = value
    return out


def _traces(fn, lam, n):
    bodies = []
    for i in range(n):
        r = _invoke(lam, fn, {"i": i})
        body = _ok(fn, r)
        assert body["rid"] == r["request_id"], (
            f"the runtime read request id {body['rid']!r}, the caller got {r['request_id']!r}")
        bodies.append((r, _fields(body["trace"])))
    return bodies


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda-Runtime-Trace-Id is a fresh X-Ray header per invocation whose Sampled flag follows
    TracingConfig: 0 under PassThrough, 1 under Active with Root and Parent matching the XRAY line.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html
    Reference: https://docs.aws.amazon.com/xray/latest/devguide/xray-concepts.html#xray-concepts-tracingheader
    """
    lam = ctx.client("lambda")
    role = _execution_role(ctx)
    fn = _function(ctx, lam, role, "trace", _make_zip([("bootstrap", BOOTSTRAP, 0o100755)]),
                   runtime="provided.al2023", handler="bootstrap",
                   TracingConfig={"Mode": "PassThrough"})

    passthrough = _traces(fn, lam, 2)
    roots = set()
    for r, f in passthrough:
        assert _ROOT.fullmatch(f["Root"]), f"Root {f.get('Root')!r} is not 1-<8 hex>-<24 hex>"
        assert _PARENT.fullmatch(f["Parent"]), f"Parent {f.get('Parent')!r} is not 16 hex digits"
        assert f["Sampled"] == "0", (
            f"under TracingConfig PassThrough with no upstream trace header the runtime was "
            f"served Sampled={f['Sampled']!r}; Lambda does not sample, so it must be '0'")
        assert "XRAY TraceId:" not in r["log"], (
            f"Lambda recorded an X-Ray trace for an unsampled PassThrough invocation: {r['log']!r}")
        roots.add(f["Root"])
    assert len(roots) == 2, f"two invocations were served the same trace Root {sorted(roots)!r}"

    lam.update_function_configuration(FunctionName=fn, TracingConfig={"Mode": "Active"})
    _wait_settled(lam, fn)
    # Active tracing samples under X-Ray's sampling rules, whose default reservoir takes the first
    # request each second (https://docs.aws.amazon.com/xray/latest/devguide/xray-concepts.html), so
    # the first Active invoke is sampled; a bounded few more absorb a sibling's custom rule.
    sampled = None
    for _ in range(5):
        r, f = _traces(fn, lam, 1)[0]
        assert _ROOT.fullmatch(f["Root"]), f"Root {f.get('Root')!r} is not 1-<8 hex>-<24 hex>"
        assert f["Root"] not in roots, f"an Active invoke reused trace Root {f['Root']!r}"
        roots.add(f["Root"])
        if f["Sampled"] == "1":
            sampled = (r, f)
            break
    assert sampled is not None, (
        "after TracingConfig Active no invocation was served Sampled=1 in five attempts; Active "
        "tracing must sample")
    r, f = sampled
    xray = re.search(r"^XRAY TraceId: (\S+)\tSegmentId: (\S+)\tSampled: (\S+)", r["log"], re.M)
    assert xray, f"no XRAY line in the log tail of a sampled Active invocation: {r['log']!r}"
    assert xray.group(1) == f["Root"], (
        f"Lambda recorded trace {xray.group(1)!r} but served the runtime Root {f['Root']!r}")
    assert xray.group(2) == f["Parent"], (
        f"Lambda's segment is {xray.group(2)!r} but the runtime was told Parent={f['Parent']!r}")
    assert xray.group(3) == "true", f"the XRAY line says Sampled: {xray.group(3)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
