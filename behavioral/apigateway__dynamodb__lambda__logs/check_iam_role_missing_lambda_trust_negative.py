"""iam-role-missing-lambda-trust-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-missing-lambda-trust-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction with a role that does not trust lambda.amazonaws.com fails with
    InvalidParameterValueException ("The role defined for the function cannot be assumed by Lambda.")
    and creates nothing; with a role trusting lambda.amazonaws.com the function is created."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Both roles are created up front: once the lambda-trusting one is usable by Lambda, the
    # root-only one created before it has propagated too, so its refusal is the trust policy's.
    bad_role_name = ctx.unique_name("sim2real-behav-badtrust-")
    bad_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    bad_role_arn = iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=json.dumps(bad_trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))

    good_role_name = ctx.unique_name("sim2real-behav-goodtrust-")
    good_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    good_role_arn = iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=json.dumps(good_trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))

    # --- positive control: role trusts lambda.amazonaws.com, function created ---
    good_func_name = ctx.unique_name("sim2real-behav-goodtrust-fn-")
    created = _retry_create_function(
        ctx,
        lam,
        dict(
            FunctionName=good_func_name,
            Runtime="python3.12",
            Role=good_role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": _simple_lambda_zip()},
            Timeout=15,
            Tags={"sim2real:managed": "true"},
        ),
        timeout_s=90.0,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_func_name))
    assert created["FunctionArn"], f"expected CreateFunction to return a FunctionArn, got {created!r}"

    # terminal read: independent of the mutating CreateFunction call, at the destination
    fetched = lam.get_function(FunctionName=good_func_name)
    assert fetched["Configuration"]["Role"] == good_role_arn, (
        f"expected GetFunction to report Role={good_role_arn!r} for the "
        f"lambda-trusted-role function, got {fetched['Configuration'].get('Role')!r}"
    )
    assert good_func_name in _function_names(lam), (
        f"expected {good_func_name!r} to be visible in ListFunctions now that its role "
        f"trusts lambda.amazonaws.com"
    )

    # --- negative: role trusts only the account root, not lambda.amazonaws.com ---
    bad_func_name = ctx.unique_name("sim2real-behav-badtrust-fn-")
    code, message = _negative_create(ctx, lam, bad_role_arn, bad_func_name)
    assert code == "InvalidParameterValueException", (
        f"expected CreateFunction against a root-only-trust role to be rejected with "
        f"InvalidParameterValueException, got {code!r}"
    )
    assert message == "The role defined for the function cannot be assumed by Lambda.", message

    # effect absent: the function was never created (independent read, not the failed call's own response)
    assert bad_func_name not in _function_names(lam), (
        f"expected {bad_func_name!r} to be absent from ListFunctions after every "
        f"CreateFunction attempt was rejected, but it is present"
    )


def _function_names(lam) -> set[str]:
    """Every function name ListFunctions reports, across all pages."""
    return {
        f["FunctionName"]
        for page in lam.get_paginator("list_functions").paginate()
        for f in page["Functions"]
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


def _negative_create(ctx, lam, role_arn: str, func_name: str,
                     attempts: int = 3) -> tuple[str | None, str | None]:
    """CreateFunction against a role with a bad trust policy, a few times a few seconds apart.
    Every attempt must fail; returns the last observed error code and message."""
    from botocore.exceptions import ClientError

    last_code = last_message = None
    for attempt in range(attempts):
        if attempt:
            time.sleep(3.0)
        try:
            result = lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _simple_lambda_zip()},
                Timeout=15,
            )
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            last_message = err.response["Error"].get("Message")
            continue
        ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
        raise AssertionError(
            f"expected CreateFunction against a root-only-trust role to be rejected, "
            f"but it SUCCEEDED and returned {result!r}"
        )
    return last_code, last_message


def _retry_create_function(ctx, lam, kwargs: dict[str, Any], timeout_s: float = 90.0) -> dict[str, Any]:
    """CreateFunction, retried while Lambda cannot yet assume the newly created role."""
    from botocore.exceptions import ClientError

    left = ctx.time_left()
    budget = timeout_s if left is None else min(timeout_s, max(left - 20, 0))
    deadline = time.monotonic() + budget
    last_err = None
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            if time.monotonic() >= deadline:
                break
            time.sleep(3.0)
    raise AssertionError(f"create_function never succeeded within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
