"""alias-revisionid-precondition."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "alias-revisionid-precondition"
GROUP = 'versions_aliases'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
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


def _wait_update_settled(lam, fn, timeout_s=90):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last.get("LastUpdateStatus") in ("Successful", "Failed", None):
            return last
        time.sleep(2.0)
    raise AssertionError(f"{fn} update not settled within {timeout_s}s. Last: {last!r}")


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
        "Tags": {"sim2real-check": CHECK},
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


def _error(fn):
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAlias rejects a stale RevisionId with PreconditionFailedException.

    DeleteAlias's real API takes no RevisionId parameter at all, so only UpdateAlias carries the
    optimistic-lock boundary here.
    """
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, "def handler(e, c): return {'marker': 'v1'}")
    v1 = lam.publish_version(FunctionName=fn)["Version"]
    lam.update_function_code(FunctionName=fn, ZipFile=_make_zip("def handler(e, c): return {'marker': 'v2'}"))
    _wait_update_settled(lam, fn)
    v2 = lam.publish_version(FunctionName=fn)["Version"]

    alias_name = ctx.unique_name("sim2real-behav-alias-")
    created = lam.create_alias(FunctionName=fn, Name=alias_name, FunctionVersion=v1)
    rev1 = created["RevisionId"]

    updated = lam.update_alias(FunctionName=fn, Name=alias_name, FunctionVersion=v2, RevisionId=rev1)
    rev2 = updated["RevisionId"]
    assert rev2 != rev1, "RevisionId must advance after a successful UpdateAlias"
    assert updated["FunctionVersion"] == v2, updated

    stale_update_code, stale_update_code_msg = _error(
        lambda: lam.update_alias(FunctionName=fn, Name=alias_name, FunctionVersion=v1, RevisionId=rev1)
    )
    assert stale_update_code == "PreconditionFailedException", (
        f"expected PreconditionFailedException, got {stale_update_code}"
    )
    assert stale_update_code_msg == (
        "The Revision Id provided does not match the latest Revision Id. "
        "Call the GetFunction/GetAlias API to retrieve the latest Revision Id"
    ), (
        f"expected the exact 'PreconditionFailedException' message, got {stale_update_code_msg!r}"
    )
    unchanged = lam.get_alias(FunctionName=fn, Name=alias_name)
    assert unchanged["FunctionVersion"] == v2, "rejected UpdateAlias must not have applied"

    restored = lam.update_alias(FunctionName=fn, Name=alias_name, FunctionVersion=v1, RevisionId=rev2)
    assert restored["FunctionVersion"] == v1, (
        "the identical UpdateAlias call must succeed once the correct RevisionId is used"
    )
    rev3 = restored["RevisionId"]
    assert rev3 != rev2, "RevisionId must advance after the restored UpdateAlias"

    lam.delete_alias(FunctionName=fn, Name=alias_name)
    gone_code, gone_code_msg = _error(lambda: lam.get_alias(FunctionName=fn, Name=alias_name))
    assert gone_code == "ResourceNotFoundException", gone_code
    assert gone_code_msg == f"Cannot find alias arn: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}:{alias_name}", (
        f"expected the exact 'ResourceNotFoundException' message, got {gone_code_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
