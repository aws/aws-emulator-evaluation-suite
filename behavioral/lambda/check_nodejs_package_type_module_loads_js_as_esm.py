"""nodejs-package-type-module-loads-js-as-esm."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "nodejs-package-type-module-loads-js-as-esm"
GROUP = 'nodejs-modules'
SERVICES = ['lambda']


_ESM_JS = r"""
export const handler = async (event) => ({ kind: 'esm', requireType: typeof require, url: import.meta.url, n: event.n + 1 });
"""
_CJS = r"""
exports.handler = async (event) => ({ kind: 'cjs', requireType: typeof require, file: __filename, n: event.n + 2 });
"""
_PKG = '{"type": "module"}'
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With "type": "module" in the package's package.json, an index.js using export syntax loads
    as an ES module, while an index.cjs in the same kind of package still loads as CommonJS.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-handler.html
    """
    lam = ctx.client("lambda")
    role = _exec_role(ctx)
    n = int(time.time()) % 900

    esm = _deploy(ctx, lam, role, {"index.js": _ESM_JS, "package.json": _PKG}, runtime="nodejs22.x")
    got = _ok(lam, esm, {"n": n})
    assert got == {"kind": "esm", "requireType": "undefined", "url": "file:///var/task/index.js", "n": n + 1}, (
        f"index.js under type=module must run as an ES module, got {got!r}"
    )

    cjs = _deploy(ctx, lam, role, {"index.cjs": _CJS, "package.json": _PKG}, runtime="nodejs22.x")
    got = _ok(lam, cjs, {"n": n})
    assert got == {"kind": "cjs", "requireType": "function", "file": "/var/task/index.cjs", "n": n + 2}, (
        f"index.cjs must run as CommonJS even under type=module, got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
