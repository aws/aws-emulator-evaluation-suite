"""update-alias-precondition-failed-stale-revision."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-alias-precondition-failed-stale-revision"
GROUP = "concurrency"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAlias with a stale RevisionId is rejected with PreconditionFailedException
    and leaves the alias's current state untouched."""
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    fn = _create_function(ctx, role_arn)

    v1 = lam.publish_version(FunctionName=fn["name"])["Version"]
    lam.update_function_code(
        FunctionName=fn["name"], ZipFile=_lambda_zip("def handler(e, c):\n    return {'v': 2}\n")
    )
    _wait_last_update_successful(ctx, fn["name"])
    v2 = lam.publish_version(FunctionName=fn["name"])["Version"]

    alias_name = ctx.unique_name("sim2real-behav-alias-")
    create_resp = lam.create_alias(FunctionName=fn["name"], Name=alias_name, FunctionVersion=v1)
    ctx.on_cleanup(lambda: _delete_alias_ignore(lam, fn["name"], alias_name))
    stale_revision = create_resp["RevisionId"]

    # A legitimate update using the correct revision succeeds and bumps the revision.
    update_resp = lam.update_alias(
        FunctionName=fn["name"], Name=alias_name, FunctionVersion=v2, RevisionId=stale_revision
    )
    current_revision = update_resp["RevisionId"]
    assert current_revision != stale_revision, "revision id did not change after a successful update"

    # Reusing the now-stale revision id must be rejected.
    code, message = _error(
        lambda: lam.update_alias(
            FunctionName=fn["name"], Name=alias_name, FunctionVersion=v1, RevisionId=stale_revision
        )
    )
    assert code == "PreconditionFailedException", f"expected PreconditionFailedException, got {code!r}"
    assert message == (
        "The Revision Id provided does not match the latest Revision Id. "
        "Call the GetFunction/GetAlias API to retrieve the latest Revision Id"
    ), f"unexpected stale-revision message, got {message!r}"

    final = lam.get_alias(FunctionName=fn["name"], Name=alias_name)
    assert final["FunctionVersion"] == v2, "alias was mutated despite the rejected stale-revision update"
    assert final["RevisionId"] == current_revision, "alias revision id drifted despite rejected update"

    # Deletes prove gone and unusable: an independent read 404s, and a mutation on the dead id also fails.
    lam.delete_alias(FunctionName=fn["name"], Name=alias_name)
    gone_code, gone_message = _error(lambda: lam.get_alias(FunctionName=fn["name"], Name=alias_name))
    assert gone_code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {gone_code!r}"
    assert gone_message == f"Cannot find alias arn: {fn['arn']}:{alias_name}", (
        f"unexpected GetAlias not-found message, got {gone_message!r}"
    )
    mutate_code, mutate_message = _error(
        lambda: lam.update_alias(FunctionName=fn["name"], Name=alias_name, FunctionVersion=v1)
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException mutating a deleted alias, got {mutate_code!r}"
    )
    assert mutate_message == f"Alias not found: {fn['arn']}:{alias_name}", (
        f"unexpected UpdateAlias not-found message, got {mutate_message!r}"
    )


def _delete_alias_ignore(lam, function_name, alias_name):
    try:
        lam.delete_alias(FunctionName=function_name, Name=alias_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """The (code, message) of a call that must fail; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _lambda_zip(handler_body: str = "def handler(event, context):\n    return {'ok': True}\n") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_body)
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_function(ctx, role_arn: str, name: str | None = None) -> dict:
    lam = ctx.client("lambda")
    fn_name = name or ctx.unique_name("sim2real-behav-fn-")
    code = _lambda_zip()
    deadline = time.monotonic() + 60.0
    resp = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code},
                Timeout=10,
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                time.sleep(2.0)
                continue
            raise
    if resp is None:
        raise AssertionError(f"function creation never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_state_active(ctx, fn_name)
    return {"name": fn_name, "arn": resp["FunctionArn"], "revision_id": resp["RevisionId"]}


def _wait_state_active(ctx, function_name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        if cfg["State"] == "Active":
            return cfg
        time.sleep(1.0)
    raise AssertionError(f"function {function_name} never became Active")


def _wait_last_update_successful(ctx, function_name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        status = cfg.get("LastUpdateStatus")
        if status == "Successful":
            return cfg
        if status == "Failed":
            raise AssertionError(f"function update failed: {cfg.get('LastUpdateStatusReason')}")
        time.sleep(1.0)
    raise AssertionError(f"function {function_name} update never completed")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
