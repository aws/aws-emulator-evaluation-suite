"""invoke-status-codes."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "invoke-status-codes"
GROUP = 'invoke_sync'
SERVICES = ['lambda']

CODE = """\
def handler(event, context):
    m = event.get("marker")
    if m:
        print("MARKER:" + m)
    return event
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_EXEC_ROLES = {}


def _exec_role_arn(ctx):
    """An execution role this check creates, shared by every function it deploys."""
    cached = _EXEC_ROLES.get(id(ctx))
    if cached is not None and cached[0] is ctx:
        return cached[1]
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
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _EXEC_ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, kwargs, timeout_s=90):
    """CreateFunction, retried while a freshly created role is not yet assumable by Lambda."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (
                err.get("Code") == "InvalidParameterValueException"
                and "cannot be assumed by Lambda" in err.get("Message", "")
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


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
    }
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    if layers:
        kwargs["Layers"] = layers
    if ephemeral_storage:
        kwargs["EphemeralStorage"] = {"Size": ephemeral_storage}
    _create_function(lam, kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _poll_log_marker(logs, fn, marker, timeout_s=60.0, interval_s=3.0):
    """Poll /aws/lambda/<fn> for a line containing marker; True once seen, else False."""
    log_group = f"/aws/lambda/{fn}"
    pattern = f'"MARKER:{marker}"'
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group, filterPattern=pattern)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            resp = {"events": []}
        if resp.get("events"):
            return True
        time.sleep(interval_s)
    return False


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RequestResponse returns 200 and echoes the payload, DryRun returns 204 with an empty body, and
    Event returns 202 with an empty body and really runs the handler, shown by a marker only the
    handler logs."""
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    marker = ctx.unique_name("sim2real-status-codes-")
    fn = _deploy_function(ctx, lam, CODE)

    payload = {"key": "value", "n": 7}
    sync = lam.invoke(
        FunctionName=fn, InvocationType="RequestResponse", Payload=json.dumps(payload).encode()
    )
    assert sync["StatusCode"] == 200, f"RequestResponse expected StatusCode 200, got {sync['StatusCode']}"
    assert "FunctionError" not in sync, f"handler raised: {sync.get('FunctionError')}"
    echoed = json.loads(sync["Payload"].read())
    assert echoed == payload, f"expected echoed payload {payload}, got {echoed}"

    dry = lam.invoke(FunctionName=fn, InvocationType="DryRun", Payload=b"{}")
    assert dry["StatusCode"] == 204, f"DryRun expected StatusCode 204, got {dry['StatusCode']}"
    assert dry["Payload"].read() == b"", "DryRun must not return a body"

    async_ = lam.invoke(
        FunctionName=fn, InvocationType="Event",
        Payload=json.dumps({"marker": marker}).encode(),
    )
    assert async_["StatusCode"] == 202, f"Event expected StatusCode 202, got {async_['StatusCode']}"
    assert async_["Payload"].read() == b"", "Event invoke must return an empty body"

    delivered = _poll_log_marker(logs, fn, marker)
    assert delivered, (
        f"async invocation marker {marker!r} never appeared in /aws/lambda/{fn} logs — "
        f"a 202 with no downstream execution is not real async delivery"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
