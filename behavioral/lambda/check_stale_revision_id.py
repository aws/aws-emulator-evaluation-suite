"""stale-revision-id."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "stale-revision-id"
GROUP = 'errors'
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


def _wait_updated(lam, fn, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        status = last.get("LastUpdateStatus")
        if status == "Failed":
            raise AssertionError(f"Function {fn} update failed: {last.get('LastUpdateStatusReason')}")
        if status == "Successful":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} updated not met within {timeout_s}s. Last: {last!r}")


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
    _create_function_retrying(lam, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError from the stale-revision call, but it succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateFunctionConfiguration with a stale RevisionId is rejected with
    PreconditionFailedException, the rejected write never lands, and the identical
    call retried with the current RevisionId then succeeds."""
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, "def handler(e, c): return e")
    config = lam.get_function_configuration(FunctionName=fn)
    stale_rev = config["RevisionId"]

    lam.update_function_configuration(FunctionName=fn, Description="bump")
    _wait_updated(lam, fn)
    current = lam.get_function_configuration(FunctionName=fn)
    current_rev = current["RevisionId"]
    assert current_rev != stale_rev, (
        f"RevisionId did not advance after a successful update: {current_rev!r} == {stale_rev!r}"
    )

    code, message = _error(
        lambda: lam.update_function_configuration(
            FunctionName=fn, Description="stale", RevisionId=stale_rev
        )
    )
    assert code == "PreconditionFailedException", (
        f"expected PreconditionFailedException for a stale RevisionId, got {code!r}"
    )
    expected = (
        "The Revision Id provided does not match the latest Revision Id. "
        "Call the GetFunction/GetAlias API to retrieve the latest Revision Id"
    )
    assert message == expected, (
        f"stale-revision UpdateFunctionConfiguration: expected message {expected!r}, got {message!r}"
    )

    after_reject = lam.get_function_configuration(FunctionName=fn)
    assert after_reject["Description"] == "bump", (
        f"rejected stale-revision update took effect: Description={after_reject['Description']!r}"
    )
    assert after_reject["RevisionId"] == current_rev, (
        f"RevisionId drifted despite the rejected update: {after_reject['RevisionId']!r} != {current_rev!r}"
    )

    lam.update_function_configuration(FunctionName=fn, Description="stale", RevisionId=current_rev)
    _wait_updated(lam, fn)
    restored = lam.get_function_configuration(FunctionName=fn)
    assert restored["Description"] == "stale", (
        f"identical update retried with the current RevisionId did not succeed: "
        f"Description={restored['Description']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
