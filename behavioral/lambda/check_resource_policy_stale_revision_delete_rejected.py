"""resource-policy-stale-revision-delete-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-stale-revision-delete-rejected"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy with a stale RevisionId is rejected with PreconditionFailedException."""
    lam = ctx.client("lambda")
    fn = _create_basic_function(ctx)

    first = lam.put_resource_policy(ResourceArn=fn["arn"], Policy=json.dumps(_policy_document(fn["arn"], "SidOne")))
    stale_revision = first["RevisionId"]
    ctx.on_cleanup(lambda: _delete_resource_policy_ignore(lam, fn["arn"]))

    # advance the revision so the one we captured above is now stale
    second = lam.put_resource_policy(ResourceArn=fn["arn"], Policy=json.dumps(_policy_document(fn["arn"], "SidTwo")))
    assert second["RevisionId"] != stale_revision, (
        f"RevisionId must advance after a successful PutResourcePolicy: "
        f"{second['RevisionId']!r} == {stale_revision!r}"
    )

    code, message = _error(
        lambda: lam.delete_resource_policy(ResourceArn=fn["arn"], RevisionId=stale_revision)
    )
    assert code == "PreconditionFailedException", f"expected PreconditionFailedException, got {code}"
    expected = (
        "The value of RevisionId provided doesn't match the policy's latest revision ID. Use the "
        "GetResourcePolicy API action to retrieve the current revision ID and try again."
    )
    assert message == expected, f"stale-revision DeleteResourcePolicy: expected message {expected!r}, got {message!r}"

    # the rejected delete must have left the policy untouched
    unchanged = lam.get_resource_policy(ResourceArn=fn["arn"])
    assert unchanged["RevisionId"] == second["RevisionId"], (
        f"a rejected DeleteResourcePolicy must not remove the policy: expected revision "
        f"{second['RevisionId']}, got {unchanged['RevisionId']}"
    )

    # the current revision should still work, and the deletion must actually take effect
    lam.delete_resource_policy(ResourceArn=fn["arn"], RevisionId=second["RevisionId"])
    gone_code, gone_message = _error(lambda: lam.get_resource_policy(ResourceArn=fn["arn"]))
    assert gone_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {gone_code}"
    expected = "The resource you requested does not exist."
    assert gone_message == expected, (
        f"GetResourcePolicy after delete: expected message {expected!r}, got {gone_message!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _policy_document(resource_arn: str, sid: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Id": "default",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "lambda:InvokeFunction",
                "Resource": resource_arn,
            }
        ],
    }


def _lambda_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_basic_function(ctx) -> dict:
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + 90
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _lambda_zip_bytes()},
                Timeout=10,
                MemorySize=128,
                Publish=False,
            )
            break
        except Exception as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValueException" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError("create_function never succeeded (role propagation timeout)")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


def _wait_function_active(ctx, name: str) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return cfg
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function did not become Active in time (last={cfg!r})")


def _delete_resource_policy_ignore(lam, resource_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        lam.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
