"""nodejs-require-in-type-module-package-rejected."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "nodejs-require-in-type-module-package-rejected"
GROUP = 'nodejs-modules'
SERVICES = ['lambda']


_REQUIRE_JS = r"""
const fs = require('fs');
exports.handler = async () => ({ ok: true });
"""
_IMPORT_JS = r"""
import fs from 'fs';
export const handler = async (event) => ({ ok: true, exists: fs.existsSync('/var/task/package.json'), id: event.id });
"""
_PKG = '{"type": "module"}'
_MESSAGE = (
    "require is not defined in ES module scope, you can use import instead\n"
    "This file is being treated as an ES module because it has a '.js' file extension and "
    "'/var/task/package.json' contains \"type\": \"module\". To treat it as a CommonJS script, "
    "rename it to use the '.cjs' file extension."
)
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


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CommonJS require() in an index.js whose package.json declares "type": "module" fails the
    invoke with FunctionError=Unhandled, ReferenceError and "require is not defined in ES module
    scope"; the same package written with import succeeds.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-handler.html
    """
    lam = ctx.client("lambda")
    role = _exec_role(ctx)

    control = _deploy(ctx, lam, role, {"index.js": _IMPORT_JS, "package.json": _PKG})
    rid = ctx.unique_name("r-")
    got = _ok(lam, control, {"id": rid})
    assert got == {"ok": True, "exists": True, "id": rid}, f"positive control (import) returned {got!r}"

    broken = _deploy(ctx, lam, role, {"index.js": _REQUIRE_JS, "package.json": _PKG})
    body = _unhandled(lam, broken, {})
    assert body["errorType"] == "ReferenceError", f"require under type=module reported {body!r}"
    assert body["errorMessage"] == _MESSAGE, f"errorMessage was {body['errorMessage']!r}"
    assert "ok" not in body, f"the failing init must not produce the handler's result: {body!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
