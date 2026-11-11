"""custom-runtime-second-answer-for-a-request-rejected."""

from __future__ import annotations

import base64
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "custom-runtime-second-answer-for-a-request-rejected"
GROUP = 'rejection'
SERVICES = ['lambda']

# "double": answer, then answer again and post an error for the same id; the outcomes are carried
# into the NEXT invocation's reply. "stale": answer this invocation for the PREVIOUS request id.
BOOTSTRAP = r'''#!/bin/sh
API="http://$AWS_LAMBDA_RUNTIME_API/2018-06-01/runtime/invocation"
CARRY=null
while true; do
  curl -sS -D /tmp/h -o /tmp/e "$API/next"
  RID=$(grep -i '^lambda-runtime-aws-request-id:' /tmp/h | tr -d '\r' | sed 's/^[^:]*: *//')
  if grep -q '"double"' /tmp/e; then
    A=$(curl -sS -o /tmp/a1 -w '%{http_code}' -X POST --data-binary '{"answer":"first"}' "$API/$RID/response")
    B=$(curl -sS -o /tmp/a2 -w '%{http_code}' -X POST --data-binary '{"answer":"second"}' "$API/$RID/response")
    C=$(curl -sS -o /tmp/a3 -w '%{http_code}' -X POST --data-binary '{"errorMessage":"late"}' "$API/$RID/error")
    CARRY=$(printf '{"rid":"%s","first":%s,"second":%s,"secondBody":%s,"error":%s,"errorBody":%s}' \
      "$RID" "$A" "$B" "$(cat /tmp/a2)" "$C" "$(cat /tmp/a3)")
    PREV=$RID
    continue
  fi
  STALE=null
  if grep -q '"stale"' /tmp/e; then
    S=$(curl -sS -o /tmp/a4 -w '%{http_code}' -X POST --data-binary '{"answer":"stale"}' "$API/$PREV/response")
    STALE=$(printf '{"status":%s,"body":%s}' "$S" "$(cat /tmp/a4)")
  fi
  printf '{"rid":"%s","carried":%s,"stale":%s}' "$RID" "$CARRY" "$STALE" > /tmp/r
  curl -sS -o /dev/null -X POST --data-binary @/tmp/r "$API/$RID/response"
done
'''

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


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A request id is answered once: a second response or a late error is refused 403
    InvalidStateTransition, and a response to a finished request id is refused 400 InvalidRequestID.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html
    """
    lam = ctx.client("lambda")
    role = _execution_role(ctx)
    fn = _function(ctx, lam, role, "twice", _make_zip([("bootstrap", BOOTSTRAP, 0o100755)]),
                   runtime="provided.al2023", handler="bootstrap")

    first = _invoke(lam, fn, {"double": True})
    assert _ok(fn, first) == {"answer": "first"}, (
        f"the caller must receive the FIRST response the runtime posted, got {first['raw']!r}")

    nxt = _invoke(lam, fn, {"report": True})
    body = _ok(fn, nxt)
    carried = body["carried"]
    assert carried["rid"] == first["request_id"], (
        f"the carried outcomes are for request {carried['rid']!r}, not {first['request_id']!r}")
    assert carried["first"] == 202, f"the first response POST was answered {carried['first']!r}"
    assert carried["second"] == 403, (
        f"a second response for an already-answered request was answered HTTP "
        f"{carried['second']!r}; it must be refused 403")
    assert carried["secondBody"] == {
        "errorMessage": "State transition from RuntimeResponseSentState to InvocationResponse "
                        "failed for runtime. Error: State transition is not allowed",
        "errorType": "InvalidStateTransition"}, f"second-response refusal: {carried['secondBody']!r}"
    assert carried["error"] == 403, (
        f"an error POST after the response was answered HTTP {carried['error']!r}; it must be "
        f"refused 403")
    assert carried["errorBody"] == {
        "errorMessage": "State transition from RuntimeResponseSentState to InvocationErrorResponse "
                        "failed for runtime. Error: State transition is not allowed",
        "errorType": "InvalidStateTransition"}, f"late-error refusal: {carried['errorBody']!r}"

    stale = _invoke(lam, fn, {"stale": True})
    body = _ok(fn, stale)
    assert body["rid"] == stale["request_id"], (
        f"the reply to the live id names {body['rid']!r}, the caller got {stale['request_id']!r}")
    assert body["stale"] == {
        "status": 400,
        "body": {"errorMessage": "Invalid request ID", "errorType": "InvalidRequestID"}}, (
        f"a response addressed to the finished request {first['request_id']!r} was answered "
        f"{body['stale']!r}; it must be refused 400 InvalidRequestID")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
