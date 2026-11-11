"""nodejs-runtime-environment-variables-identify-runtime."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "nodejs-runtime-environment-variables-identify-runtime"
GROUP = 'nodejs-environment'
SERVICES = ['lambda']


_HANDLER = r"""
exports.handler = async () => {
  const e = process.env;
  const keys = ['AWS_EXECUTION_ENV', 'AWS_LAMBDA_FUNCTION_NAME', 'AWS_LAMBDA_FUNCTION_MEMORY_SIZE',
    'AWS_LAMBDA_FUNCTION_VERSION', 'AWS_REGION', 'AWS_DEFAULT_REGION', 'LAMBDA_TASK_ROOT',
    'LAMBDA_RUNTIME_DIR', '_HANDLER', 'AWS_LAMBDA_LOG_GROUP_NAME', 'TZ', 'LANG', 'CUSTOM_SETTING'];
  const out = {};
  for (const k of keys) out[k] = e[k] === undefined ? null : e[k];
  out.runtimeApiSet = typeof e.AWS_LAMBDA_RUNTIME_API === 'string' && e.AWS_LAMBDA_RUNTIME_API.length > 0;
  out.nodeMajor = process.versions.node.split('.')[0];
  out.cwd = process.cwd();
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
    """Node.js reserved environment variables describe the runtime and function: AWS_EXECUTION_ENV is
    "AWS_Lambda_<runtime>", name, memory, version, region, handler and log group match, task root
    and working directory are /var/task, TZ is ":UTC", and custom variables pass through.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
    """
    lam = ctx.client("lambda")
    role = _exec_role(ctx)
    custom = ctx.unique_name("v-")
    for runtime, major in (("nodejs22.x", "22"), ("nodejs24.x", "24")):
        fn = _deploy(ctx, lam, role, {"index.js": _HANDLER}, runtime=runtime,
                     env={"CUSTOM_SETTING": custom})
        got = _ok(lam, fn, {})
        want = {
            "AWS_EXECUTION_ENV": f"AWS_Lambda_{runtime}",
            "AWS_LAMBDA_FUNCTION_NAME": fn,
            "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": "128",
            "AWS_LAMBDA_FUNCTION_VERSION": "$LATEST",
            "AWS_REGION": ctx.region,
            "AWS_DEFAULT_REGION": ctx.region,
            "LAMBDA_TASK_ROOT": "/var/task",
            "LAMBDA_RUNTIME_DIR": "/var/runtime",
            "_HANDLER": "index.handler",
            "AWS_LAMBDA_LOG_GROUP_NAME": f"/aws/lambda/{fn}",
            "TZ": ":UTC",
            "LANG": "en_US.UTF-8",
            "CUSTOM_SETTING": custom,
            "runtimeApiSet": True,
            "nodeMajor": major,
            "cwd": "/var/task",
        }
        diff = {k: (want[k], got.get(k)) for k in want if got.get(k) != want[k]}
        assert not diff, f"{runtime}: environment mismatches (expected, got): {diff!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
