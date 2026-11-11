"""python-non-serializable-return-rejected-with-marshal-error."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "python-non-serializable-return-rejected-with-marshal-error"
GROUP = "python-runtime"
SERVICES = ["lambda"]

_HANDLER = """\
import datetime
import uuid

ENV_ID = uuid.uuid4().hex
CALLS = 0


def handler(event, context):
    global CALLS
    CALLS += 1
    kind = event["kind"]
    if kind == "set":
        return {1, 2}
    if kind == "object":
        return object()
    if kind == "datetime":
        return {"at": datetime.datetime(2020, 1, 2, 3, 4, 5)}
    return {"kind": kind, "env": ENV_ID, "calls": CALLS}
"""

# kind -> the Python type name json.dumps refuses
_REFUSED = {"set": "set", "object": "object", "datetime": "datetime"}


_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 2, interval_s: float = 2.0,
                    budget_s: float = 40.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent; raise if not."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _role(ctx) -> str:
    """An execution role this check owns. It grants nothing, so the function writes no logs."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-pyrt-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _wait_ready(lam, fn: str, timeout_s: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed" or last.get("LastUpdateStatus") == "Failed":
            raise AssertionError(f"{fn} failed: {last.get('StateReason')!r} "
                                 f"{last.get('LastUpdateStatusReason')!r}")
        if last["State"] == "Active" and last.get("LastUpdateStatus") in (None, "Successful"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} never became Active/Successful in {timeout_s}s; last={last!r}")


def _deploy(ctx, lam, role: str, files: dict, *, handler: str = "index.handler",
            runtime: str = "python3.12", timeout: int = 10, memory: int = 128,
            environment: dict | None = None) -> str:
    """Create a zip-packaged function, register its teardown, and wait until it is Active."""
    fn = ctx.unique_name("sim2real-behav-pyrt-")
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    kwargs = dict(FunctionName=fn, Role=role, Runtime=runtime, Handler=handler,
                  Code={"ZipFile": _zip(files)}, Timeout=timeout, MemorySize=memory,
                  Tags={"sim2real": CHECK})
    if environment is not None:
        kwargs["Environment"] = {"Variables": environment}
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            # IAM propagation exposes no pollable condition; the bounded retry is the fix.
            if "cannot be assumed" in exc.response["Error"].get("Message", "") \
                    and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn),
                             "ResourceNotFoundException"))
    _wait_ready(lam, fn)
    return fn


def _invoke(lam, fn: str, payload: bytes | None = b"{}", **kwargs) -> dict:
    """A RequestResponse invoke, returning status, function error, request id and raw body."""
    args = dict(FunctionName=fn, InvocationType="RequestResponse", **kwargs)
    if payload is not None:
        args["Payload"] = payload
    resp = lam.invoke(**args)
    return {
        "status": resp["StatusCode"],
        "error": resp.get("FunctionError"),
        "version": resp.get("ExecutedVersion"),
        "request_id": resp["ResponseMetadata"]["RequestId"],
        "raw": resp["Payload"].read(),
    }


def _ok(lam, fn: str, payload: bytes | None = b"{}", **kwargs):
    """The parsed body of an invoke that must succeed."""
    r = _invoke(lam, fn, payload, **kwargs)
    assert r["status"] == 200 and r["error"] is None, (
        f"{fn}: expected a clean 200, got status={r['status']!r} FunctionError={r['error']!r} "
        f"body={r['raw'][:400]!r}"
    )
    return json.loads(r["raw"])


def _error(fn) -> tuple:
    """``(code, message)`` of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A return value the runtime cannot serialize (set, object, datetime) fails with
    Runtime.MarshalError "Unable to marshal response: Object of type <type> is not JSON
    serializable", the invoke's requestId and an empty stackTrace; the function keeps serving.
    """
    lam = ctx.client("lambda")
    fn = _deploy(ctx, lam, _role(ctx), {"index.py": _HANDLER})

    before = _ok(lam, fn, json.dumps({"kind": "ok"}).encode())
    assert before["kind"] == "ok", f"control return value {before!r}"

    for kind, type_name in _REFUSED.items():
        r = _invoke(lam, fn, json.dumps({"kind": kind}).encode())
        assert r["status"] == 200, f"{kind}: StatusCode {r['status']!r}; a function error is 200"
        assert r["error"] == "Unhandled", (
            f"{kind}: FunctionError={r['error']!r}, expected 'Unhandled'; body {r['raw'][:300]!r}"
        )
        body = json.loads(r["raw"])
        assert body["errorType"] == "Runtime.MarshalError", (
            f"{kind}: errorType {body['errorType']!r}, expected 'Runtime.MarshalError'"
        )
        want = f"Unable to marshal response: Object of type {type_name} is not JSON serializable"
        assert body["errorMessage"] == want, (
            f"{kind}: errorMessage {body['errorMessage']!r}, expected {want!r}"
        )
        assert body["requestId"] == r["request_id"], (
            f"{kind}: error requestId does not equal the invoke's x-amzn-RequestId "
            f"({len(body['requestId'])} vs {len(r['request_id'])} chars)"
        )
        assert body["stackTrace"] == [], f"{kind}: stackTrace {body['stackTrace']!r}, expected []"

    after = _ok(lam, fn, json.dumps({"kind": "ok"}).encode())
    assert after["kind"] == "ok", (
        f"after three marshal failures the same function must still serve, got {after!r}"
    )
    if after["env"] == before["env"]:
        want_calls = before["calls"] + len(_REFUSED) + 1
        assert after["calls"] == want_calls, (
            f"calls went {before['calls']!r} -> {after['calls']!r} in one environment across "
            f"{len(_REFUSED)} marshal failures; expected {want_calls!r}, proving the handler "
            "body really ran (and returned) on each refused invoke rather than being "
            "short-circuited"
        )
    else:
        assert after["calls"] == 1, (
            f"environment {after['env']!r} is fresh (unlike {before['env']!r}), so its own "
            f"counter must start at 1, got calls={after['calls']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
