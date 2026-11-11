"""nodejs-builtin-sdk-v3-clients-resolve-without-bundling."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "nodejs-builtin-sdk-v3-clients-resolve-without-bundling"
GROUP = 'nodejs-environment'
SERVICES = ['lambda']


_HANDLER = r"""
exports.handler = async () => {
  const out = {};
  for (const name of ['@aws-sdk/client-s3', '@aws-sdk/client-dynamodb', '@aws-sdk/lib-dynamodb']) {
    const mod = require(name);
    out[name] = Object.keys(mod).filter((k) => /^[A-Z][A-Za-z0-9]*Client$/.test(k)).sort();
  }
  out.commandType = typeof require('@aws-sdk/client-s3').GetObjectCommand;
  try { require('aws-sdk'); out.v2 = 'resolved'; } catch (e) { out.v2 = e.code + ': ' + e.message.split('\n')[0]; }
  return out;
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Node.js 22 or 24 function bundling no dependencies can require the runtime-provided AWS SDK
    v3 (@aws-sdk/client-s3, client-dynamodb, lib-dynamodb export their clients and commands),
    while the v2 'aws-sdk' package fails with MODULE_NOT_FOUND.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-nodejs.html
    """
    lam = ctx.client("lambda")
    role = _exec_role(ctx)
    for runtime in ("nodejs22.x", "nodejs24.x"):
        fn = _deploy(ctx, lam, role, {"index.js": _HANDLER}, runtime=runtime)
        got = _ok(lam, fn, {})
        assert got == {
            "@aws-sdk/client-s3": ["S3Client"],
            "@aws-sdk/client-dynamodb": ["DynamoDBClient"],
            "@aws-sdk/lib-dynamodb": ["DynamoDBDocumentClient"],
            "commandType": "function",
            "v2": "MODULE_NOT_FOUND: Cannot find module 'aws-sdk'",
        }, f"{runtime}: runtime-provided SDK resolution returned {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
