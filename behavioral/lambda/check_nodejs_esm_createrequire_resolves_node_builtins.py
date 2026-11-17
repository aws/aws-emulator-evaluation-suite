"""nodejs-esm-createrequire-resolves-node-builtins."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "nodejs-esm-createrequire-resolves-node-builtins"
GROUP = "nodejs-modules"
SERVICES = ["lambda", "iam"]


_PKG = '{"type": "module"}\n'
_HANDLER_JS = r"""
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
export const handler = async (event) => ({
  joined: require("node:path").join("a", "b"),
  formatType: typeof require("node:util").format,
  n: event.n,
});
"""
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


def _deploy(ctx, lam, role: str, runtime: str) -> str:
    """Create a function from the shared ESM handler under ``runtime``, wait for Active."""
    name = ctx.unique_name("sim2real-behav-fn-")
    kwargs = dict(
        FunctionName=name, Runtime=runtime, Handler="index.handler", Role=role,
        Code={"ZipFile": _zip({"index.js": _HANDLER_JS, "package.json": _PKG})},
        MemorySize=128, Timeout=10, Tags={"sim2real": CHECK},
    )
    deadline = time.monotonic() + 90
    while True:
        try:
            resp = lam.create_function(**kwargs)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (err["Code"] == "InvalidParameterValueException"
                           and err.get("Message") == _ROLE_NOT_READY)
            if not propagating or time.monotonic() > deadline:
                raise
            time.sleep(3)
    assert resp["Runtime"] == runtime, f"CreateFunction echoed Runtime={resp['Runtime']!r}, expected {runtime!r}"
    ctx.on_cleanup(_teardown(lambda n=name: lam.delete_function(FunctionName=n),
                             "ResourceNotFoundException"))
    deadline = time.monotonic() + 90
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        assert cfg["State"] != "Failed", f"{name} ({runtime}) entered Failed: {cfg.get('StateReason')!r}"
        if cfg["State"] == "Active":
            return name
        assert time.monotonic() < deadline, f"{name} ({runtime}) not Active within 90s; last {cfg['State']!r}"
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ES module handler's ``require`` from ``createRequire(import.meta.url)`` loads
    ``node:path`` and ``node:util``: the invoke succeeds with the joined path and
    ``typeof ... .format === "function"``, under both nodejs22.x and nodejs24.x.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-handler.html
    Reference: https://nodejs.org/api/module.html#modulecreaterequirefilename
    """
    lam = ctx.client("lambda")
    role = _exec_role(ctx)

    for runtime in ("nodejs22.x", "nodejs24.x"):
        fn = _deploy(ctx, lam, role, runtime)
        n = len(runtime)
        got = _ok(lam, fn, {"n": n})
        assert got == {"joined": "a/b", "formatType": "function", "n": n}, (
            f"{runtime}: invoke returned {got!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
