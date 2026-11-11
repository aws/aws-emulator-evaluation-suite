"""resource-policy-revisionid-precondition."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "resource-policy-revisionid-precondition"
GROUP = 'permissions'
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
    _create_function_retrying(lam, **kwargs)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises,
    because an emulator accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_resource_policy_quietly(lam, arn):
    try:
        lam.delete_resource_policy(ResourceArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy/DeleteResourcePolicy reject a mismatched RevisionId with
    PreconditionFailedException."""
    lam = ctx.client("lambda")
    # Put/Get/DeleteResourcePolicy are recent additions absent from older botocore builds; without
    # them there is no way to exercise this contract, so skip rather than fail (missing prerequisite).
    if not (hasattr(lam, "get_resource_policy") and hasattr(lam, "put_resource_policy")
            and hasattr(lam, "delete_resource_policy")):
        raise AssertionError("Put/Get/DeleteResourcePolicy not available in the installed botocore")

    fn = _deploy_function(ctx, lam, "def handler(e, c): return e")
    fn_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "sim2realbehavrevlock",
                    "Effect": "Allow",
                    "Principal": {"AWS": _account_id(ctx)},
                    "Action": "lambda:GetFunction",
                    "Resource": fn_arn,
                }
            ],
        }
    )
    put1 = lam.put_resource_policy(ResourceArn=fn_arn, Policy=policy_doc)
    ctx.on_cleanup(lambda: _delete_resource_policy_quietly(lam, fn_arn))
    rev1 = put1["RevisionId"]

    mismatched_rev = "00000000-0000-0000-0000-000000000000"
    mismatched_code, mismatched_msg = _error(
        lambda: lam.put_resource_policy(
            ResourceArn=fn_arn, Policy=policy_doc, RevisionId=mismatched_rev
        )
    )
    assert mismatched_code == "PreconditionFailedException", (
        f"expected PreconditionFailedException, got {mismatched_code}"
    )
    expected = (
        "The value of RevisionId provided doesn't match the policy's latest revision ID. Use the "
        "GetResourcePolicy API action to retrieve the current revision ID and try again."
    )
    assert mismatched_msg == expected, (
        f"mismatched-revision PutResourcePolicy: expected message {expected!r}, got {mismatched_msg!r}"
    )
    unchanged_after_reject = lam.get_resource_policy(ResourceArn=fn_arn)
    assert unchanged_after_reject["RevisionId"] == rev1, (
        f"a rejected PutResourcePolicy must not advance the revision: expected {rev1}, "
        f"got {unchanged_after_reject['RevisionId']}"
    )

    put2 = lam.put_resource_policy(ResourceArn=fn_arn, Policy=policy_doc, RevisionId=rev1)
    rev2 = put2["RevisionId"]
    assert rev2 != rev1, "RevisionId must advance after a successful PutResourcePolicy"

    stale_delete_code, stale_delete_msg = _error(
        lambda: lam.delete_resource_policy(ResourceArn=fn_arn, RevisionId=rev1)
    )
    assert stale_delete_code == "PreconditionFailedException", (
        f"expected PreconditionFailedException, got {stale_delete_code}"
    )
    expected = (
        "The value of RevisionId provided doesn't match the policy's latest revision ID. Use the "
        "GetResourcePolicy API action to retrieve the current revision ID and try again."
    )
    assert stale_delete_msg == expected, (
        f"stale-revision DeleteResourcePolicy: expected message {expected!r}, got {stale_delete_msg!r}"
    )
    unchanged_after_stale_delete = lam.get_resource_policy(ResourceArn=fn_arn)
    assert unchanged_after_stale_delete["RevisionId"] == rev2, (
        f"a rejected DeleteResourcePolicy must not remove the policy: expected revision {rev2}, "
        f"got {unchanged_after_stale_delete['RevisionId']}"
    )

    lam.delete_resource_policy(ResourceArn=fn_arn, RevisionId=rev2)
    gone_code, gone_msg = _error(lambda: lam.get_resource_policy(ResourceArn=fn_arn))
    assert gone_code == "ResourceNotFoundException", gone_code
    expected = "The resource you requested does not exist."
    assert gone_msg == expected, (
        f"GetResourcePolicy after delete: expected message {expected!r}, got {gone_msg!r}"
    )

    # Measured, not assumed: DeleteResourcePolicy is idempotent and returns 204 on an
    # already-deleted policy, even though GetResourcePolicy on the same ARN reports
    # ResourceNotFoundException (asserted above).
    redelete = lam.delete_resource_policy(ResourceArn=fn_arn)
    assert redelete["ResponseMetadata"]["HTTPStatusCode"] == 204, (
        f"DeleteResourcePolicy on an already-deleted policy should still succeed idempotently, "
        f"got {redelete['ResponseMetadata']['HTTPStatusCode']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
