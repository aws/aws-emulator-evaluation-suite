"""stdlib-imports."""

from __future__ import annotations

import hashlib
import io
import json
import textwrap
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "stdlib-imports"
GROUP = 'compute'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _exec_role_arn(ctx):
    """An execution role this check creates (once per run) and deletes in cleanup."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function_retrying(lam, **kwargs):
    """CreateFunction, retried while the role this check just created propagates in IAM."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function_url_config(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(lam, fn, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _deploy_function(ctx, lam, code, *, name=None, handler="index.handler",
                     runtime="python3.12", memory=128, timeout=30, environment=None,
                     layers=None, ephemeral_storage=None, role=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Handler": handler,
        "Role": role or _exec_role_arn(ctx),
        "Code": {"ZipFile": _make_zip(code)},
        "MemorySize": memory,
        "Timeout": timeout,
        "Tags": {"sim2real-behav-check": CHECK},
    }
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    if layers:
        kwargs["Layers"] = layers
    if ephemeral_storage:
        kwargs["EphemeralStorage"] = {"Size": ephemeral_storage}
    _create_function_retrying(lam, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _invoke_sync(lam, fn, payload):
    resp = lam.invoke(
        FunctionName=fn, InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    body = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(
            f"Function {fn} returned FunctionError={resp['FunctionError']}: {body.decode()[:500]}"
        )
    return json.loads(body) if body else None


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Standard library modules are importable (json, hashlib, os, sys, uuid)."""
    lam = ctx.client("lambda")
    runtime = "python3.12"
    code = """\
import json, hashlib, os, sys, uuid
def handler(event, context):
    return {
        "python_version": list(sys.version_info[:2]),
        "pid": os.getpid(),
        "uuid_str": str(uuid.uuid4()),
        "md5": hashlib.md5(b"test").hexdigest(),
    }
"""
    fn = _deploy_function(ctx, lam, code, runtime=runtime)
    resp = _invoke_sync(lam, fn, {})

    expected_version = [int(p) for p in runtime.removeprefix("python").split(".")]
    assert resp["python_version"] == expected_version, (
        f"runtime={runtime!r} declares sys.version_info[:2]=={expected_version!r}, "
        f"the handler reported {resp['python_version']!r}"
    )
    assert resp["pid"] > 0, f"expected a positive pid from os.getpid(), got {resp['pid']!r}"
    reported_uuid = uuid.UUID(resp["uuid_str"])
    assert reported_uuid.version == 4, (
        f"expected uuid.uuid4() to mint a version-4 UUID, got {resp['uuid_str']!r} "
        f"(version {reported_uuid.version})"
    )
    expected_md5 = hashlib.md5(b"test").hexdigest()
    assert resp["md5"] == expected_md5, (
        f"expected hashlib.md5(b'test').hexdigest() == {expected_md5!r}, got {resp['md5']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
