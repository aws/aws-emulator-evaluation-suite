"""check-lambda-role-trust-policy-required."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "check-lambda-role-trust-policy-required"
GROUP = "arn-resolution"
SERVICES = ["dynamodb", "kinesis", "lambda"]


def _trust_policy(principal: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": principal},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _zip_code() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "index.py", "def handler(event, context):\n    return {'ok': True}\n"
        )
    return buf.getvalue()


def _create_function(lam, fn_name, role_arn):
    return lam.create_function(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_code()},
    )


def _create_function_with_retry(lam, fn_name, role_arn, timeout_s=90.0, interval_s=3.0):
    """CreateFunction, retrying ONLY the transient IAM-propagation rejection (a just-fixed
    trust policy has not yet propagated) through the deadline. Any other error is raised
    immediately: this must not paper over the deterministic rejection under test."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _create_function(lam, fn_name, role_arn)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            if (
                code == "InvalidParameterValueException"
                and "cannot be assumed" in message
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _assert_function_gone(lam, fn_name, account_id):
    try:
        lam.get_function(FunctionName=fn_name)
    except ClientError as exc:
        assert exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for {fn_name} after the rejected create, "
            f"got {exc.response.get('Error', {})}"
        )
        fn_arn = f"arn:aws:lambda:{lam.meta.region_name}:{account_id}:function:{fn_name}"
        assert exc.response["Error"].get("Message") == f"Function not found: {fn_arn}", (
            exc.response["Error"]
        )
    else:
        raise AssertionError(
            f"CreateFunction for {fn_name} raised, yet GetFunction finds it — the rejected "
            f"function was created anyway"
        )


@tags("axis:rejection", "cap:c1", "plane:control", "concern:e2e")
def run(ctx) -> None:
    """A Lambda function cannot be created with an IAM role whose trust policy doesn't include
    lambda.amazonaws.com — and once the SAME role's trust policy is fixed, the identical
    CreateFunction call succeeds."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    control_role_name = ctx.unique_name("role-trust-ok-")
    control_role = iam.create_role(
        RoleName=control_role_name,
        AssumeRolePolicyDocument=_trust_policy("lambda.amazonaws.com"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=control_role_name))

    broken_role_name = ctx.unique_name("role-no-trust-")
    broken_role = iam.create_role(
        RoleName=broken_role_name,
        AssumeRolePolicyDocument=_trust_policy("ec2.amazonaws.com"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=broken_role_name))

    # ---- positive control: a role trusting lambda.amazonaws.com is accepted ----
    control_fn_name = ctx.unique_name("fn-trust-ok-")
    _create_function_with_retry(lam, control_fn_name, control_role["Role"]["Arn"])
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=control_fn_name))
    control_cfg = lam.get_function(FunctionName=control_fn_name)["Configuration"]
    assert control_cfg["FunctionName"] == control_fn_name, (
        f"the control function is not visible via an independent GetFunction read: "
        f"{control_cfg!r}"
    )

    # ---- break exactly one thing: the role's trust policy names ec2, not lambda ----
    broken_fn_name = ctx.unique_name("fn-no-trust-")
    denied = None
    try:
        _create_function(lam, broken_fn_name, broken_role["Role"]["Arn"])
    except ClientError as exc:
        denied = exc.response.get("Error", {})
    else:
        raise AssertionError(
            f"CreateFunction succeeded with role {broken_role_name} whose trust policy "
            f"allows only ec2.amazonaws.com to assume it"
        )
    assert denied.get("Code") == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for a role lacking lambda.amazonaws.com "
        f"in its trust policy, got {denied!r}"
    )
    assert denied.get("Message") == "The role defined for the function cannot be assumed by Lambda.", (
        f"expected the exact role-trust message, got {denied!r}"
    )

    # ---- the effect is absent: the rejected function does not exist ----
    _assert_function_gone(lam, broken_fn_name, broken_role["Role"]["Arn"].split(":")[4])

    # ---- restore: fix the SAME role's trust policy, then the identical call succeeds ----
    iam.update_assume_role_policy(
        RoleName=broken_role_name,
        PolicyDocument=_trust_policy("lambda.amazonaws.com"),
    )
    _create_function_with_retry(lam, broken_fn_name, broken_role["Role"]["Arn"])
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=broken_fn_name))
    restored_cfg = lam.get_function(FunctionName=broken_fn_name)["Configuration"]
    assert restored_cfg["FunctionName"] == broken_fn_name, (
        f"the restored function is not visible via an independent GetFunction read: "
        f"{restored_cfg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
