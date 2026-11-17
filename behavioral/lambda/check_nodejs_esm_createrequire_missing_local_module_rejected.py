"""nodejs-esm-createrequire-missing-local-module-rejected."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "nodejs-esm-createrequire-missing-local-module-rejected"
GROUP = "nodejs-modules"
SERVICES = ["lambda", "iam"]


_PKG = '{"type": "module"}\n'
_GOOD_JS = r"""
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
export const handler = async (event) => ({ joined: require("node:path").join("a", event.id) });
"""
_MISSING_JS = r"""
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
export const handler = async () => ({ loaded: require("./sim2real-missing-module") });
"""
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."
_EXPECT_ERROR = (
    "Error",
    "Cannot find module './sim2real-missing-module'\nRequire stack:\n- /var/task/index.js",
)


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


def _deploy(ctx, lam, role: str, files: dict) -> str:
    """Create a function from inline ``files``, wait for Active, and register its delete."""
    name = ctx.unique_name("sim2real-behav-fn-")
    kwargs = dict(
        FunctionName=name, Runtime="nodejs22.x", Handler="index.handler", Role=role,
        Code={"ZipFile": _zip(files)}, MemorySize=128, Timeout=10, Tags={"sim2real": CHECK},
    )
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
    ctx.on_cleanup(_teardown(lambda n=name: lam.delete_function(FunctionName=n),
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


def expect_error(fn, code: str, message: str) -> None:
    """``fn()`` must report exactly ``(code, message)`` as a FunctionError=Unhandled envelope."""
    assert fn() == (code, message)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ``require`` built by ``createRequire(import.meta.url)`` behaves like CommonJS
    ``require``: a path with nothing at it fails the invoke Unhandled with errorType "Error"
    and "Cannot find module" plus its require stack, while resolving ``node:path`` succeeds.

    Reference: https://nodejs.org/api/module.html#modulecreaterequirefilename
    """
    lam = ctx.client("lambda")
    role = _exec_role(ctx)
    rid = ctx.unique_name("r-")

    control = _deploy(ctx, lam, role, {"index.js": _GOOD_JS, "package.json": _PKG})
    got = _ok(lam, control, {"id": rid})
    assert got == {"joined": f"a/{rid}"}, f"positive control returned {got!r}"

    broken = _deploy(ctx, lam, role, {"index.js": _MISSING_JS, "package.json": _PKG})

    def call():
        body = _unhandled(lam, broken, {})
        return body["errorType"], body["errorMessage"]

    expect_error(call, *_EXPECT_ERROR)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
