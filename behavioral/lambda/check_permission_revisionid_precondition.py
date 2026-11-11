"""permission-revisionid-precondition."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "permission-revisionid-precondition"
GROUP = 'permissions'
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
        "Tags": {"sim2real": "permission-revisionid-precondition"},
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddPermission/RemovePermission reject a stale RevisionId with PreconditionFailedException."""
    lam = ctx.client("lambda")
    fn = _deploy_function(ctx, lam, "def handler(e, c): return e")

    stmt_id = "sim2realbehavrevlockperm"
    lam.add_permission(
        FunctionName=fn,
        StatementId=stmt_id,
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn=f"arn:aws:s3:::{ctx.unique_name('sim2real-behav-bucket-')}",
    )
    # AddPermission's response only carries the added Statement, not a RevisionId — fetch the
    # current RevisionId via GetPolicy instead.
    rev1 = lam.get_policy(FunctionName=fn)["RevisionId"]

    stmt_id_2 = "sim2realbehavrevlockperm2"
    stale_add_code, stale_add_code_msg = _error(
        lambda: lam.add_permission(
            FunctionName=fn,
            StatementId=stmt_id_2,
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
            SourceArn=f"arn:aws:s3:::{ctx.unique_name('sim2real-behav-bucket-')}",
            RevisionId="00000000-0000-0000-0000-000000000000",
        )
    )
    assert stale_add_code == "PreconditionFailedException", (
        f"expected PreconditionFailedException, got {stale_add_code}"
    )
    assert stale_add_code_msg == "The Revision Id provided does not match the latest Revision Id. Call the GetPolicy API to retrieve the latest Revision Id", (
        f"expected the exact 'PreconditionFailedException' message, got {stale_add_code_msg!r}"
    )
    policy_after_reject = lam.get_policy(FunctionName=fn)
    doc = json.loads(policy_after_reject["Policy"])
    assert not any(s["Sid"] == stmt_id_2 for s in doc["Statement"]), "rejected AddPermission must not persist"
    assert policy_after_reject["RevisionId"] == rev1, "a rejected AddPermission must not advance RevisionId"

    lam.add_permission(
        FunctionName=fn,
        StatementId=stmt_id_2,
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn=f"arn:aws:s3:::{ctx.unique_name('sim2real-behav-bucket-')}",
        RevisionId=rev1,
    )
    rev2 = lam.get_policy(FunctionName=fn)["RevisionId"]
    assert rev2 != rev1, "RevisionId must advance after a successful AddPermission"

    stale_remove_code, stale_remove_code_msg = _error(
        lambda: lam.remove_permission(FunctionName=fn, StatementId=stmt_id, RevisionId=rev1)
    )
    assert stale_remove_code == "PreconditionFailedException", (
        f"expected PreconditionFailedException, got {stale_remove_code}"
    )
    assert stale_remove_code_msg == "The Revision Id provided does not match the latest Revision Id. Call the GetPolicy API to retrieve the latest Revision Id", (
        f"expected the exact 'PreconditionFailedException' message, got {stale_remove_code_msg!r}"
    )
    policy_after_remove_reject = lam.get_policy(FunctionName=fn)
    doc_after_remove_reject = json.loads(policy_after_remove_reject["Policy"])
    assert any(s["Sid"] == stmt_id for s in doc_after_remove_reject["Statement"]), (
        "rejected RemovePermission must not remove the statement"
    )
    assert policy_after_remove_reject["RevisionId"] == rev2, (
        "a rejected RemovePermission must not advance RevisionId"
    )

    lam.remove_permission(FunctionName=fn, StatementId=stmt_id, RevisionId=rev2)
    policy_after_remove = lam.get_policy(FunctionName=fn)
    doc_after_remove = json.loads(policy_after_remove["Policy"])
    assert not any(s["Sid"] == stmt_id for s in doc_after_remove["Statement"]), (
        "RemovePermission with the correct RevisionId must remove the statement"
    )
    rev3 = policy_after_remove["RevisionId"]
    assert rev3 != rev2, "RevisionId must advance after a successful RemovePermission"

    lam.remove_permission(FunctionName=fn, StatementId=stmt_id_2, RevisionId=rev3)
    no_policy_code, no_policy_code_msg = _error(lambda: lam.get_policy(FunctionName=fn))
    assert no_policy_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException once every statement is removed, got {no_policy_code}"
    )
    assert no_policy_code_msg == "The resource you requested does not exist.", (
        f"expected the exact 'ResourceNotFoundException' message, got {no_policy_code_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
