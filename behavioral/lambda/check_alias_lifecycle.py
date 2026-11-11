"""alias-lifecycle."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "alias-lifecycle"
GROUP = 'versions_aliases'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"
HANDLER_V2 = "def handler(event, context): return {'marker': 'v2', 'echo': event}"


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
    while time.monotonic() < deadline:
        if lam.get_function_configuration(FunctionName=fn).get("LastUpdateStatus") in ("Successful", "Failed", None):
            return
        time.sleep(1.0)


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
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Alias create/read/update/delete transitions and post-delete 404, reflected in list.

    Covers: duplicate-name ResourceConflict, UpdateAlias moving the version (with RevisionId advance),
    a stale-RevisionId PreconditionFailed rejection, list reflection, and DeleteAlias -> 404.
    """
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, HANDLER_V1)
    v1 = lam.publish_version(FunctionName=fn)["Version"]

    alias_name = "sim2real-behav-live"
    alias_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}:{alias_name}"
    created = lam.create_alias(
        FunctionName=fn, Name=alias_name, FunctionVersion=v1, Description="v1 alias"
    )
    assert created["FunctionVersion"] == v1
    rev1 = created["RevisionId"]

    got = lam.get_alias(FunctionName=fn, Name=alias_name)
    assert got["FunctionVersion"] == v1
    assert got["AliasArn"] == created["AliasArn"]

    # Boundary: a duplicate CreateAlias for the same Name is rejected.
    dup_code, dup_code_msg = _error(
        lambda: lam.create_alias(FunctionName=fn, Name=alias_name, FunctionVersion=v1)
    )
    assert dup_code == "ResourceConflictException", f"expected ResourceConflictException, got {dup_code}"
    assert dup_code_msg == f"Alias already exists: {alias_arn}", (
        f"expected the exact 'ResourceConflictException' message, got {dup_code_msg!r}"
    )
    after_dup = lam.get_alias(FunctionName=fn, Name=alias_name)
    assert after_dup["FunctionVersion"] == v1, "rejected duplicate CreateAlias must not have altered the alias"
    assert after_dup["RevisionId"] == rev1, "rejected duplicate CreateAlias must not have advanced the revision"

    # Publish a second version and move the alias to it.
    lam.update_function_code(FunctionName=fn, ZipFile=_make_zip(HANDLER_V2))
    _wait_update_settled(lam, fn)
    v2 = lam.publish_version(FunctionName=fn)["Version"]

    updated = lam.update_alias(FunctionName=fn, Name=alias_name, FunctionVersion=v2, RevisionId=rev1)
    assert updated["FunctionVersion"] == v2
    assert updated["RevisionId"] != rev1, "RevisionId must change after a successful UpdateAlias"

    # Boundary: reusing the now-stale RevisionId is rejected (optimistic locking).
    stale_code, stale_code_msg = _error(
        lambda: lam.update_alias(FunctionName=fn, Name=alias_name, FunctionVersion=v1, RevisionId=rev1)
    )
    assert stale_code == "PreconditionFailedException", f"expected PreconditionFailedException, got {stale_code}"
    assert stale_code_msg == (
        "The Revision Id provided does not match the latest Revision Id. "
        "Call the GetFunction/GetAlias API to retrieve the latest Revision Id"
    ), (
        f"expected the exact 'PreconditionFailedException' message, got {stale_code_msg!r}"
    )
    unchanged = lam.get_alias(FunctionName=fn, Name=alias_name)
    assert unchanged["FunctionVersion"] == v2, "rejected stale-RevisionId UpdateAlias must not have applied"

    listed = lam.list_aliases(FunctionName=fn)["Aliases"]
    assert any(a["Name"] == alias_name and a["FunctionVersion"] == v2 for a in listed), listed

    lam.delete_alias(FunctionName=fn, Name=alias_name)
    code, code_msg = _error(lambda: lam.get_alias(FunctionName=fn, Name=alias_name))
    assert code == "ResourceNotFoundException", f"expected alias gone, got {code}"
    assert code_msg == f"Cannot find alias arn: {alias_arn}", (
        f"expected the exact 'ResourceNotFoundException' message, got {code_msg!r}"
    )
    listed2 = lam.list_aliases(FunctionName=fn)["Aliases"]
    assert not any(a["Name"] == alias_name for a in listed2), listed2

    # A mutation against the now-dead alias name must also fail, not just the read.
    post_delete_update_code, post_delete_update_code_msg = _error(
        lambda: lam.update_alias(FunctionName=fn, Name=alias_name, FunctionVersion=v2)
    )
    assert post_delete_update_code == "ResourceNotFoundException", (
        f"expected UpdateAlias on a deleted alias to fail not-found, got {post_delete_update_code}"
    )
    assert post_delete_update_code_msg == f"Alias not found: {alias_arn}", (
        f"expected the exact 'ResourceNotFoundException' message, got {post_delete_update_code_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
