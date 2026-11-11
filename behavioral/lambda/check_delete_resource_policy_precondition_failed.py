"""delete-resource-policy-precondition-failed."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-precondition-failed"
GROUP = "concurrency"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy with a stale RevisionId is rejected with
    PreconditionFailedException and leaves the resource policy intact."""
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    fn = _create_function(ctx, role_arn)
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(lam, fn["arn"]))

    policy_v1 = json.dumps(
        {
            "Version": "2012-10-17",
            "Id": "default",
            "Statement": [
                {
                    "Sid": "AllowSnsInvoke",
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "lambda:InvokeFunction",
                    "Resource": fn["arn"],
                }
            ],
        }
    )
    put1 = lam.put_resource_policy(ResourceArn=fn["arn"], Policy=policy_v1)
    stale_revision = put1["RevisionId"]

    policy_v2 = json.dumps(
        {
            "Version": "2012-10-17",
            "Id": "default",
            "Statement": [
                {
                    "Sid": "AllowSnsInvoke",
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "lambda:InvokeFunction",
                    "Resource": fn["arn"],
                },
                {
                    "Sid": "AllowEventsInvoke",
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "lambda:InvokeFunction",
                    "Resource": fn["arn"],
                },
            ],
        }
    )
    put2 = lam.put_resource_policy(ResourceArn=fn["arn"], Policy=policy_v2, RevisionId=stale_revision)
    current_revision = put2["RevisionId"]
    assert current_revision != stale_revision, "revision id did not change after a successful update"

    code, code_msg = _client_error(
        lambda: lam.delete_resource_policy(ResourceArn=fn["arn"], RevisionId=stale_revision)
    )
    assert code == "PreconditionFailedException", f"expected PreconditionFailedException, got {code!r}"
    expected_code_msg = (
        "The value of RevisionId provided doesn't match the policy's latest revision ID. "
        "Use the GetResourcePolicy API action to retrieve the current revision ID and try again."
    )
    assert code_msg == expected_code_msg, (
        f"expected message {expected_code_msg!r}, got {code_msg!r}"
    )

    after = lam.get_resource_policy(ResourceArn=fn["arn"])
    assert after["RevisionId"] == current_revision, "policy revision drifted despite rejected delete"
    statements = json.loads(after["Policy"])["Statement"]
    sids = {s["Sid"] for s in statements}
    assert sids == {"AllowSnsInvoke", "AllowEventsInvoke"}, f"policy content changed unexpectedly: {sids}"

    # restore: the identical delete, now given the correct (current) RevisionId, must succeed —
    # without this leg a target that rejects every RevisionId-qualified delete would also pass.
    lam.delete_resource_policy(ResourceArn=fn["arn"], RevisionId=current_revision)
    gone_code, gone_code_msg = _client_error(lambda: lam.get_resource_policy(ResourceArn=fn["arn"]))
    assert gone_code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {gone_code!r}"
    expected_gone_code_msg = "The resource you requested does not exist."
    assert gone_code_msg == expected_gone_code_msg, (
        f"expected message {expected_gone_code_msg!r}, got {gone_code_msg!r}"
    )


def _client_error(fn):
    """(code, message) of a call that must be refused; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _safe_delete_resource_policy(lam, resource_arn):
    try:
        lam.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
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
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code},
                Timeout=10,
                Tags={"sim2real:managed": "true"},
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


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
