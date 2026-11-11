"""invoke-with-response-stream-ec2-errors."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "invoke-with-response-stream-ec2-errors"
GROUP = 'invoke_sync'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"


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
        "Tags": {"sim2real-behavioral-check": "invoke-with-response-stream-ec2-errors"},
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


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c3", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeWithResponseStream rejects a nonexistent function or qualifier before opening a stream,
    and a valid streaming invoke streams the correct payload. The declared EC2* errors arise only
    from internal ENI provisioning and cannot be forced, so they are not exercised.
    """
    lam = ctx.client("lambda")
    missing_name = ctx.unique_name("sim2real-behav-fn-missing-")

    def _invoke_missing():
        resp = lam.invoke_with_response_stream(FunctionName=missing_name, Payload=b"{}")
        for _ in resp["EventStream"]:
            pass
        return resp["StatusCode"]

    fn_arn_prefix = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:"
    missing_code, missing_msg = _error(_invoke_missing)
    assert missing_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent function, got {missing_code}"
    )
    expected_missing = f"Function not found: {fn_arn_prefix}{missing_name}:$LATEST"
    assert missing_msg == expected_missing, f"expected message {expected_missing!r}, got {missing_msg!r}"

    fn = _deploy_function(ctx, lam, HANDLER_V1)
    v1 = lam.publish_version(FunctionName=fn)["Version"]
    bogus_qualifier = str(int(v1) + 1000)

    def _invoke_bad_qualifier():
        resp = lam.invoke_with_response_stream(
            FunctionName=fn, Qualifier=bogus_qualifier, Payload=b"{}"
        )
        for _ in resp["EventStream"]:
            pass
        return resp["StatusCode"]

    qual_code, qual_msg = _error(_invoke_bad_qualifier)
    assert qual_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent qualifier, got {qual_code}"
    )
    expected_qual = f"Function not found: {fn_arn_prefix}{fn}:{bogus_qualifier}"
    assert qual_msg == expected_qual, f"expected message {expected_qual!r}, got {qual_msg!r}"

    # Baseline: a valid streaming invoke actually streams the correct payload.
    resp = lam.invoke_with_response_stream(
        FunctionName=fn, Payload=json.dumps({"mode": "echo"}).encode("utf-8")
    )
    chunks = bytearray()
    saw_complete = False
    for event in resp["EventStream"]:
        if "PayloadChunk" in event:
            chunks.extend(event["PayloadChunk"]["Payload"])
        elif "InvokeComplete" in event:
            saw_complete = True
            assert not event["InvokeComplete"].get("ErrorCode"), event
    assert saw_complete, "expected an InvokeComplete terminal event on the stream"
    decoded = json.loads(bytes(chunks))
    assert decoded["marker"] == "v1", decoded


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
