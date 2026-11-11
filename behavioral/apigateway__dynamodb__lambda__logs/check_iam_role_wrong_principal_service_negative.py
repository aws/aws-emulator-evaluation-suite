"""iam-role-wrong-principal-service-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-wrong-principal-service-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateFunctionConfiguration to a role trusting only ec2.amazonaws.com fails with
    InvalidParameterValueException and leaves the function's Role unchanged; an update to a
    second role trusting lambda.amazonaws.com succeeds and sets Role to it."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    # bootstrap: a function with a properly-trusted role
    role_a_name = ctx.unique_name("sim2real-behav-wrongprincipal-a-")
    role_a_arn = iam.create_role(
        RoleName=role_a_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy("lambda.amazonaws.com")),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_a_name))

    func_name = ctx.unique_name("sim2real-behav-wrongprincipal-fn-")
    created = _retry_create_function(
        lam,
        dict(
            FunctionName=func_name,
            Runtime="python3.12",
            Role=role_a_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": _simple_lambda_zip()},
            Timeout=15,
            Tags={"sim2real-check": CHECK},
        ),
        timeout_s=90.0,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    assert created["FunctionArn"], f"create_function returned no FunctionArn: {created!r}"
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=func_name)["State"],
        lambda s: s == "Active",
        timeout_s=60.0,
        interval_s=2.0,
    )

    # --- negative: try to re-point the function at a role trusting ec2.amazonaws.com ---
    role_ec2_name = ctx.unique_name("sim2real-behav-wrongprincipal-ec2-")
    role_ec2_arn = iam.create_role(
        RoleName=role_ec2_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy("ec2.amazonaws.com")),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_ec2_name))

    code = _retry_negative_update(ctx, lam, func_name, role_ec2_arn)
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException re-pointing the function at an "
        f"ec2.amazonaws.com-trusted role, got {code!r}"
    )

    # effect absent: the function's role was not changed
    current_role = lam.get_function_configuration(FunctionName=func_name)["Role"]
    assert current_role == role_a_arn, (
        f"expected the rejected update to leave Role unchanged at {role_a_arn!r}, "
        f"got {current_role!r}"
    )

    # --- positive control: update to another role that DOES trust lambda.amazonaws.com ---
    role_b_name = ctx.unique_name("sim2real-behav-wrongprincipal-b-")
    role_b_arn = iam.create_role(
        RoleName=role_b_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy("lambda.amazonaws.com")),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_b_name))

    _retry_positive_update(lam, func_name, role_b_arn, timeout_s=90.0)
    final_role = lam.get_function_configuration(FunctionName=func_name)["Role"]
    assert final_role == role_b_arn, (
        f"expected UpdateFunctionConfiguration to a lambda.amazonaws.com-trusted role "
        f"to succeed and set Role to {role_b_arn!r}, got {final_role!r}"
    )


def _trust_policy(service: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _simple_lambda_zip() -> bytes:
    src = (
        "def handler(event, context):\n"
        "    return {'statusCode': 200}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _retry_create_function(lam, kwargs: dict[str, Any], timeout_s: float = 90.0) -> dict[str, Any]:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            time.sleep(3.0)
    raise AssertionError(f"create_function never succeeded within {timeout_s}s: {last_err}")


def _retry_negative_update(ctx, lam, func_name: str, role_arn: str, attempts: int = 3) -> str | None:
    """UpdateFunctionConfiguration against a wrongly-trusted role, a few times a few seconds
    apart, stopping early if the time budget runs low. Every attempt should fail; returns None
    if one succeeds, else the last observed error code."""
    from botocore.exceptions import ClientError

    last_code = None
    for attempt in range(attempts):
        if attempt:
            left = ctx.time_left()
            if left is not None and left < 30:
                break
            time.sleep(3.0)
        try:
            lam.update_function_configuration(FunctionName=func_name, Role=role_arn)
            return None
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
    return last_code


def _retry_positive_update(lam, func_name: str, role_arn: str, timeout_s: float = 90.0) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            lam.update_function_configuration(FunctionName=func_name, Role=role_arn)
            return
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            time.sleep(3.0)
    raise AssertionError(f"update_function_configuration never succeeded within {timeout_s}s: {last_err}")


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
