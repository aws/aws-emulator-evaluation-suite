"""custom-runtime-error-post-body-and-type-header-shape-the-error-payload."""

from __future__ import annotations

import base64
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "custom-runtime-error-post-body-and-type-header-shape-the-error-payload"
GROUP = 'error-propagation'
SERVICES = ['lambda']

# Each arm posts to .../<id>/error with a different header/body combination.
BOOTSTRAP = r'''#!/bin/sh
API="http://$AWS_LAMBDA_RUNTIME_API/2018-06-01/runtime/invocation"
while true; do
  curl -sS -D /tmp/h -o /tmp/e "$API/next"
  RID=$(grep -i '^lambda-runtime-aws-request-id:' /tmp/h | tr -d '\r' | sed 's/^[^:]*: *//')
  ARM=$(sed -n 's/.*"arm" *: *"\([^"]*\)".*/\1/p' /tmp/e)
  case "$ARM" in
    header-only)
      curl -sS -o /dev/null -X POST -H 'Lambda-Runtime-Function-Error-Type: Function.HeaderOnly' \
        --data-binary '' "$API/$RID/error" ;;
    both)
      curl -sS -o /dev/null -X POST -H 'Lambda-Runtime-Function-Error-Type: Runtime.FromHeader' \
        --data-binary '{"errorType":"Body.FromBody","errorMessage":"body side"}' "$API/$RID/error" ;;
    not-json)
      curl -sS -o /dev/null -X POST --data-binary 'this is not json' "$API/$RID/error" ;;
    *)
      printf '{"rid":"%s"}' "$RID" > /tmp/r
      curl -sS -o /dev/null -X POST --data-binary @/tmp/r "$API/$RID/response" ;;
  esac
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A custom runtime's .../error body is returned verbatim whatever the error-type header says, an
    empty body yields exactly {"errorType": <header>}, and a non-JSON body is returned as-is typed
    application/octet-stream, each with FunctionError=Unhandled.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html
    """
    lam = ctx.client("lambda")
    role = _execution_role(ctx)
    fn = _function(ctx, lam, role, "errshape", _make_zip([("bootstrap", BOOTSTRAP, 0o100755)]),
                   runtime="provided.al2023", handler="bootstrap")

    control = _invoke(lam, fn, {"arm": "ok"})
    assert _ok(fn, control) == {"rid": control["request_id"]}, f"control: {control['raw']!r}"

    both = _invoke(lam, fn, {"arm": "both"})
    doc = _failed(fn, both)
    assert doc == {"errorType": "Body.FromBody", "errorMessage": "body side"}, (
        f"with both a body and a Lambda-Runtime-Function-Error-Type header the caller got {doc!r}; "
        f"the body the runtime posted must be returned unchanged, not rewritten from the header "
        f"'Runtime.FromHeader'")

    header_only = _invoke(lam, fn, {"arm": "header-only"})
    doc = _failed(fn, header_only)
    assert doc == {"errorType": "Function.HeaderOnly"}, (
        f"an empty error body with header Function.HeaderOnly produced {doc!r}; Lambda builds "
        f"exactly {{'errorType': <header value>}} when the runtime posts no ErrorRequest")

    not_json = _invoke(lam, fn, {"arm": "not-json"})
    assert not_json["function_error"] == "Unhandled", (
        f"an error POST with a non-JSON body reported FunctionError="
        f"{not_json['function_error']!r}: {not_json['raw']!r}")
    assert not_json["raw"] == b"this is not json", (
        f"a non-JSON error body reached the caller as {not_json['raw']!r}; it must be returned "
        f"verbatim, not wrapped in a synthesised error document")
    assert not_json["content_type"] == "application/octet-stream", (
        f"the non-JSON error body was typed {not_json['content_type']!r}, expected "
        f"'application/octet-stream'")

    # effect-absent: none of the errors leaked a success body, and the runtime still answers
    for r in (both, header_only, not_json):
        assert b'"rid"' not in r["raw"], f"an error invocation also carried a response: {r['raw']!r}"
    after = _invoke(lam, fn, {"arm": "ok"})
    assert _ok(fn, after) == {"rid": after["request_id"]}, f"after the errors: {after['raw']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
