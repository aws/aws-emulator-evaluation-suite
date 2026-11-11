"""context-object."""

from __future__ import annotations

import io
import json
import re
import textwrap
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


_REQUEST_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


CHECK = "context-object"
GROUP = 'compute'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLES: dict = {}


def _role_arn(ctx):
    """Create this check's own Lambda execution role once per run and register its cleanup."""
    import json as _json

    held = _ROLES.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY))
    _ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only while a freshly created role is not yet assumable."""
    from botocore.exceptions import ClientError as _ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except _ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = err.get("Code") == "InvalidParameterValueException" and "cannot be assumed" in err.get("Message", "")
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3)


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
        "Role": role or _role_arn(ctx),
        "Code": {"ZipFile": _make_zip(code)},
        "MemorySize": memory,
        "Timeout": timeout,
        "Tags": {"sim2real:managed": "true"},
    }
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    if layers:
        kwargs["Layers"] = layers
    if ephemeral_storage:
        kwargs["EphemeralStorage"] = {"Size": ephemeral_storage}
    _create_function(lam, **kwargs)
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
    """The runtime context object exposes function_name, memory, arn, request_id, remaining_time."""
    lam = ctx.client("lambda")
    code = """\
def handler(event, context):
    return {
        "function_name": context.function_name,
        "memory_limit": context.memory_limit_in_mb,
        "invoked_arn": context.invoked_function_arn,
        "request_id": context.aws_request_id,
        "remaining_ms": context.get_remaining_time_in_millis(),
    }
"""
    fn = _deploy_function(ctx, lam, code, memory=256, timeout=30)
    account = ctx.client("sts").get_caller_identity()["Account"]
    resp = _invoke_sync(lam, fn, {})
    assert resp["function_name"] == fn, (
        f"expected context.function_name={fn!r}, got {resp['function_name']!r}"
    )
    assert int(resp["memory_limit"]) == 256, (
        f"expected context.memory_limit_in_mb=256, got {resp['memory_limit']!r}"
    )
    expected_arn_prefix = f"arn:aws:lambda:{ctx.region}:{account}:function:{fn}"
    assert resp["invoked_arn"].startswith(expected_arn_prefix), (
        f"expected context.invoked_function_arn to start with {expected_arn_prefix!r}, "
        f"got {resp['invoked_arn']!r}"
    )
    assert _REQUEST_ID_RE.match(str(resp["request_id"])), (
        f"expected context.aws_request_id to be a UUID, got {resp['request_id']!r}"
    )
    assert 0 < resp["remaining_ms"] <= 30000, (
        f"expected 0 < context.get_remaining_time_in_millis() <= 30000, got {resp['remaining_ms']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
