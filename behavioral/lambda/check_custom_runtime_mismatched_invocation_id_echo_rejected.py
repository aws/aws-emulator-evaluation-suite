"""custom-runtime-mismatched-invocation-id-echo-rejected."""

from __future__ import annotations

import base64
import io
import json
import re
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "custom-runtime-mismatched-invocation-id-echo-rejected"
GROUP = 'rejection'
SERVICES = ['lambda']

# The runtime posts the reply once with a WRONG Lambda-Runtime-Invocation-Id, then with the one it
# was served, and reports both outcomes in the reply that is accepted.
BOOTSTRAP = r'''#!/bin/sh
API="http://$AWS_LAMBDA_RUNTIME_API/2018-06-01/runtime/invocation"
while true; do
  curl -sS -D /tmp/h -o /tmp/e "$API/next"
  RID=$(grep -i '^lambda-runtime-aws-request-id:' /tmp/h | tr -d '\r' | sed 's/^[^:]*: *//')
  INV=$(grep -i '^lambda-runtime-invocation-id:' /tmp/h | tr -d '\r' | sed 's/^[^:]*: *//')
  if grep -q '"mismatch"' /tmp/e; then
    B=$(curl -sS -o /tmp/b -w '%{http_code}' -X POST -H "Lambda-Runtime-Invocation-Id: $BOGUS" \
      --data-binary '{"answer":"wrong-attempt"}' "$API/$RID/response")
    printf '{"rid":"%s","inv":"%s","badStatus":%s,"badBody":%s}' "$RID" "$INV" "$B" "$(cat /tmp/b)" > /tmp/r
    curl -sS -o /dev/null -X POST -H "Lambda-Runtime-Invocation-Id: $INV" --data-binary @/tmp/r "$API/$RID/response"
  else
    printf '{"rid":"%s","inv":"%s"}' "$RID" "$INV" > /tmp/r
    curl -sS -o /dev/null -X POST -H "Lambda-Runtime-Invocation-Id: $INV" --data-binary @/tmp/r "$API/$RID/response"
  fi
done
'''

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

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
    """A response echoing the wrong Lambda-Runtime-Invocation-Id is refused 400 InvalidInvocationId
    and never reaches the caller; the right echo is delivered, and each invocation id is fresh.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html
    """
    lam = ctx.client("lambda")
    role = _execution_role(ctx)
    bogus = str(uuid.uuid4())
    fn = _function(ctx, lam, role, "invid", _make_zip(
        [("bootstrap", BOOTSTRAP.replace("$BOGUS", bogus), 0o100755)]),
        runtime="provided.al2023", handler="bootstrap")

    control = _invoke(lam, fn, {"leg": "control"})
    c = _ok(fn, control)
    assert c["rid"] == control["request_id"], f"control reply names {c['rid']!r}"
    assert _UUID.fullmatch(c["inv"]) and c["inv"] != c["rid"], (
        f"Lambda-Runtime-Invocation-Id was {c['inv']!r}; it must be a uuid distinct from the "
        f"request id {c['rid']!r}")

    r = _invoke(lam, fn, {"mismatch": True})
    body = _ok(fn, r)
    assert body.get("answer") != "wrong-attempt", (
        f"the response posted with a mismatched invocation id reached the caller: {body!r}")
    assert body["rid"] == r["request_id"], f"the delivered reply names {body['rid']!r}"
    assert body["badStatus"] == 400, (
        f"a response echoing invocation id {bogus!r} instead of the served one was answered HTTP "
        f"{body['badStatus']!r}; it must be refused 400")
    assert body["badBody"] == {"errorMessage": "Invalid invocation ID",
                               "errorType": "InvalidInvocationId"}, (
        f"the refusal body was {body['badBody']!r}")
    assert _UUID.fullmatch(body["inv"]) and body["inv"] not in (c["inv"], bogus), (
        f"the second invocation was served invocation id {body['inv']!r}; each attempt gets a new one")
    assert body["inv"] != body["rid"], (
        f"Lambda-Runtime-Invocation-Id was {body['inv']!r}, equal to the request id "
        f"{body['rid']!r}; it must be distinct")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
