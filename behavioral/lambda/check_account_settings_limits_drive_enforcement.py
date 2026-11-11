"""account-settings-limits-drive-enforcement."""

from __future__ import annotations

import io
import json
import os
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "account-settings-limits-drive-enforcement"
GROUP = 'packaging'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _make_oversized_zip(min_size_bytes):
    """A real, syntactically-valid deployment package whose ON-DISK zip size is comfortably
    >= min_size_bytes, using ZIP_STORED (no compression) plus incompressible random padding."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("index.py", "def handler(event, context):\n    return event\n")
        zf.writestr("padding.bin", os.urandom(min_size_bytes))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _role_arn(ctx):
    """Create this run's own Lambda execution role (once per run) and return its ARN."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_ready = (err.get("Code") == "InvalidParameterValueException"
                         and err.get("Message") == _ROLE_NOT_READY)
            if not not_ready or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _cleanup_fn(ctx, lam, name):
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


def _deploy_function(ctx, lam, code, *, name=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam,
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_role_arn(ctx),
        Code={"ZipFile": _make_zip(code)},
        MemorySize=128,
        Timeout=30,
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _error(fn):
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction enforces GetAccountSettings' CodeSizeZipped: a small package deploys, while
    one over the limit gets RequestEntityTooLargeException and leaves no function behind."""
    lam = ctx.client("lambda")
    settings = lam.get_account_settings()
    account_limit = settings["AccountLimit"]
    zipped_limit = account_limit["CodeSizeZipped"]
    assert isinstance(zipped_limit, int) and zipped_limit > 0, account_limit

    role_arn = _role_arn(ctx)

    # A function comfortably WITHIN the reported limit succeeds.
    _deploy_function(ctx, lam, HANDLER_V1, name=ctx.unique_name("sim2real-behav-fn-within-limit-"))

    over_name = ctx.unique_name("sim2real-behav-fn-over-limit-")
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, over_name))
    oversized_zip = _make_oversized_zip(zipped_limit + 6 * 1024 * 1024)
    assert len(oversized_zip) > zipped_limit, (len(oversized_zip), zipped_limit)

    code, code_msg = _error(
        lambda: _create_function(lam,
            FunctionName=over_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": oversized_zip},
            Timeout=10,
        )
    )
    assert code == "RequestEntityTooLargeException", (
        f"expected CreateFunction to reject a {len(oversized_zip)}-byte deployment package, which exceeds "
        f"the account's reported CodeSizeZipped limit of {zipped_limit} bytes, with RequestEntityTooLargeException, "
        f"got {code!r}"
    )
    assert code_msg == "Request must be smaller than 70167211 bytes for the CreateFunction operation", (
        f"expected the exact 'RequestEntityTooLargeException' message, got {code_msg!r}"
    )

    gone, gone_msg = _error(lambda: lam.get_function(FunctionName=over_name))
    assert gone == "ResourceNotFoundException", (
        f"a rejected oversized CreateFunction must not leave a function behind, got {gone}"
    )
    assert gone_msg == f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{over_name}", (
        f"expected the exact 'ResourceNotFoundException' message, got {gone_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
