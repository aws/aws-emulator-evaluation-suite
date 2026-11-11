"""invoke-log-result."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "invoke-log-result"
GROUP = 'invoke_sync'
SERVICES = ['lambda']


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
        "Tags": {"sim2real:managed": "true"},
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """LogType=Tail's inline LogResult tail agrees with the log CloudWatch Logs independently persists."""
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    import base64

    name = ctx.unique_name("sim2real-behav-fn-")
    marker = f"SIM2REAL-LOG-{name}"
    code = f"def handler(e, c):\n    print({marker!r})\n    return {{}}"
    fn = _deploy_function(ctx, lam, code, name=name)

    resp = lam.invoke(FunctionName=fn, Payload=b"{}", LogType="Tail")
    assert resp["StatusCode"] == 200, f"Invoke StatusCode expected 200, got {resp['StatusCode']!r}"
    log_result = resp.get("LogResult")
    assert log_result, "Invoke with LogType=Tail returned no LogResult header"
    decoded = base64.b64decode(log_result).decode("utf-8", errors="replace")
    assert marker in decoded, (
        f"expected marker {marker!r} in the inline LogResult tail, got: {decoded[:300]!r}"
    )

    log_group = f"/aws/lambda/{fn}"

    def _marker_in_cloudwatch() -> bool:
        try:
            cw = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{marker}"')
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return False
            raise
        return any(marker in e.get("message", "") for e in cw.get("events", []))

    deadline = time.monotonic() + 60.0
    found = _marker_in_cloudwatch()
    while not found and time.monotonic() < deadline:
        time.sleep(2.0)
        found = _marker_in_cloudwatch()
    assert found, (
        f"marker {marker!r} was in the inline LogResult tail but never appeared in the "
        f"independently-read CloudWatch Logs group {log_group} within 60s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
