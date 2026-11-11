"""nodejs-process-exit-reports-exit-error-and-reinitializes-rejected."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "nodejs-process-exit-reports-exit-error-and-reinitializes-rejected"
GROUP = 'nodejs-errors'
SERVICES = ['lambda']


_HANDLER = r"""
const initId = require('crypto').randomUUID();
let calls = 0;
exports.handler = async (event) => {
  calls += 1;
  if (event.exit !== undefined) process.exit(event.exit);
  if (event.throw) throw new Error('handled failure');
  return { initId, calls };
};
"""
# ===== helpers =====
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


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


def _exec_role(ctx) -> str:
    """This check's own execution role. It carries no policy, so the function cannot write a log
    group: nothing outlives the function's delete."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _deploy(ctx, lam, role: str, files: dict, *, runtime: str = "nodejs22.x",
            handler: str = "index.handler", env: dict | None = None, timeout: int = 10) -> str:
    """Create a function from inline ``files``, wait for Active, and register its delete."""
    name = ctx.unique_name("sim2real-behav-fn-")
    kwargs = dict(
        FunctionName=name, Runtime=runtime, Handler=handler, Role=role,
        Code={"ZipFile": _zip(files)}, MemorySize=128, Timeout=timeout,
        Tags={"sim2real": CHECK},
    )
    if env is not None:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (err["Code"] == "InvalidParameterValueException"
                           and err.get("Message") == _ROLE_NOT_READY)
            if not propagating or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    deadline = time.monotonic() + 90
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        assert cfg["State"] != "Failed", f"{name} entered State=Failed: {cfg.get('StateReason')!r}"
        if cfg["State"] == "Active":
            return name
        assert time.monotonic() < deadline, f"{name} not Active within 90s; last {cfg['State']!r}"
        time.sleep(1)


def _invoke(lam, name: str, payload) -> tuple:
    """RequestResponse invoke: ``(FunctionError or None, raw payload bytes)``; HTTP 200 asserted."""
    resp = lam.invoke(FunctionName=name, InvocationType="RequestResponse",
                      Payload=json.dumps(payload).encode())
    assert resp["StatusCode"] == 200, f"Invoke {name}: StatusCode {resp['StatusCode']!r}, expected 200"
    return resp.get("FunctionError"), resp["Payload"].read()


def _ok(lam, name: str, payload):
    """Invoke and return the decoded result, failing on any FunctionError."""
    err, raw = _invoke(lam, name, payload)
    assert err is None, f"Invoke {name}: FunctionError={err!r}, payload {raw[:600]!r}"
    return json.loads(raw)


def _unhandled(lam, name: str, payload) -> dict:
    """Invoke and return the error envelope, requiring FunctionError=Unhandled."""
    err, raw = _invoke(lam, name, payload)
    assert err == "Unhandled", f"Invoke {name}: FunctionError={err!r}, expected 'Unhandled'; payload {raw[:600]!r}"
    body = json.loads(raw)
    assert isinstance(body, dict), f"Invoke {name}: error payload {body!r} is not an object"
    return body


def _invoke_with_id(lam, name: str, payload) -> tuple:
    """Invoke; ``(FunctionError, decoded payload, request id from the response metadata)``."""
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode())
    assert resp["StatusCode"] == 200, f"Invoke {name}: StatusCode {resp['StatusCode']!r}"
    return (resp.get("FunctionError"), json.loads(resp["Payload"].read()),
            resp["ResponseMetadata"]["RequestId"])


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """process.exit() in a Node.js handler fails the invoke with Runtime.ExitError naming the request
    id and exit status (or "Runtime exited without providing a reason" for 0), and the next invoke
    runs a fresh init; a thrown error keeps the warm module state.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/troubleshooting-invocation.html
    """
    lam = ctx.client("lambda")
    fn = _deploy(ctx, lam, _exec_role(ctx), {"index.js": _HANDLER})

    err, first, _ = _invoke_with_id(lam, fn, {})
    assert err is None and first["calls"] == 1, f"first invoke: FunctionError={err!r}, payload {first!r}"
    err, body, _ = _invoke_with_id(lam, fn, {"throw": True})
    assert err == "Unhandled" and body["errorMessage"] == "handled failure", f"throw: {err!r} {body!r}"
    err, kept, _ = _invoke_with_id(lam, fn, {})
    assert err is None, f"after a thrown error: FunctionError={err!r}, payload {kept!r}"
    assert kept["initId"] == first["initId"] and kept["calls"] == first["calls"] + 2, (
        f"a thrown error must not reset the environment; before {first!r}, after {kept!r}"
    )

    err, body, request_id = _invoke_with_id(lam, fn, {"exit": 3})
    assert err == "Unhandled", f"exit(3): FunctionError={err!r}, payload {body!r}"
    assert body["errorType"] == "Runtime.ExitError", f"exit(3) reported {body!r}"
    assert body["errorMessage"] == f"RequestId: {request_id} Error: Runtime exited with error: exit status 3", (
        f"exit(3): errorMessage {body['errorMessage']!r}; request id {request_id!r}"
    )
    err, fresh, _ = _invoke_with_id(lam, fn, {})
    assert err is None, f"after exit(3): FunctionError={err!r}, payload {fresh!r}"
    assert fresh["calls"] == 1 and fresh["initId"] != first["initId"], (
        f"the environment that exited must not serve again: after exit(3) got {fresh!r} "
        f"(exited environment {first!r})"
    )

    err, body, request_id = _invoke_with_id(lam, fn, {"exit": 0})
    assert err == "Unhandled", f"exit(0): FunctionError={err!r}, payload {body!r}"
    assert body == {
        "errorType": "Runtime.ExitError",
        "errorMessage": f"RequestId: {request_id} Error: Runtime exited without providing a reason",
    }, f"exit(0) reported {body!r}; request id {request_id!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
