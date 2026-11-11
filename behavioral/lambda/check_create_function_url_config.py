"""create-function-url-config."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-function-url-config"
GROUP = 'function_url'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_ASSUMABLE = "The role defined for the function cannot be assumed by Lambda."
_ROLES = []


def _delete_role(iam, name):
    for call in (
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY),
        lambda: iam.delete_role(RoleName=name),
    ):
        try:
            call()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise


def _execution_role(ctx):
    """The execution role this check creates for its functions, one per run."""
    for owner, arn in _ROLES:
        if owner is ctx:
            return arn
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lam-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY)
    _ROLES.append((ctx, arn))
    return arn


def _call_create_function(lam, **kwargs):
    """CreateFunction, retried while IAM propagates the execution role this check created."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (
                err.get("Code") != "InvalidParameterValueException"
                or err.get("Message") != _ROLE_NOT_ASSUMABLE
                or time.monotonic() > deadline
            ):
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
        "Role": role or _execution_role(ctx),
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
    _call_create_function(lam, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFunctionUrlConfig returns a well-formed FunctionUrl."""
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, "def handler(e, c): return {'statusCode': 200, 'body': 'ok'}")
    # AWS_IAM keeps the URL private: only signed callers this account authorizes can invoke it.
    resp = lam.create_function_url_config(FunctionName=fn, AuthType="AWS_IAM")
    url = resp["FunctionUrl"]
    assert url.startswith("https://"), f"FunctionUrl must be an https URL, got {url!r}"
    # Verify Get round-trips
    get = lam.get_function_url_config(FunctionName=fn)
    assert get["FunctionUrl"] == url, (
        f"GetFunctionUrlConfig must echo the same FunctionUrl issued by Create, "
        f"created={url!r} got={get['FunctionUrl']!r}"
    )
    assert get["AuthType"] == "AWS_IAM", f"expected AuthType=AWS_IAM, got {get['AuthType']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
