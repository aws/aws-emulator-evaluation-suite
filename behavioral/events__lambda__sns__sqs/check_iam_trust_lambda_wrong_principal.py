"""iam-trust-lambda-wrong-principal."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-trust-lambda-wrong-principal"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "sns", "sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Lambda must refuse to use an execution role whose trust policy does not trust
    lambda.amazonaws.com, leave no function behind, while the identical call with a
    correctly-trusting role succeeds."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    zip_bytes = _lambda_zip("def handler(event, context):\n    return {'ok': True}\n")
    basic_exec_policy_arn = (
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )

    # --- broken: role trusts sqs.amazonaws.com, not lambda.amazonaws.com ---
    bad_role_name = ctx.unique_name("role-wrongtrust-")
    bad_role = iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy("sqs.amazonaws.com")),
        Tags=[{"Key": "sim2real", "Value": "iam-trust-lambda-wrong-principal"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))
    iam.attach_role_policy(RoleName=bad_role_name, PolicyArn=basic_exec_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=bad_role_name, PolicyArn=basic_exec_policy_arn
        )
    )
    _poll_until(
        lambda: _role_exists(iam, bad_role_name),
        lambda ok: ok,
        timeout_s=20,
        interval_s=1,
    )

    bad_fn_name = ctx.unique_name("fn-wrongtrust-")
    code, message = _error(
        lambda: lam.create_function(
            FunctionName=bad_fn_name,
            Runtime="python3.12",
            Role=bad_role["Role"]["Arn"],
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Tags={"sim2real": "iam-trust-lambda-wrong-principal"},
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected Lambda to reject a role that does not trust lambda.amazonaws.com "
        f"with InvalidParameterValueException, got {code!r}"
    )
    assert message == "The role defined for the function cannot be assumed by Lambda.", (
        f"expected Lambda's trust-rejection message, got {message!r}"
    )

    not_found_code, not_found_message = _error(lambda: lam.get_function(FunctionName=bad_fn_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected no function to have been created for the rejected role, "
        f"get_function returned {not_found_code!r}"
    )
    expected_not_found = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_fn_name}"
    )
    assert not_found_message == expected_not_found, (
        f"expected GetFunction's not-found message {expected_not_found!r}, got {not_found_message!r}"
    )

    # --- positive control: identical flow with a correctly-trusting role succeeds ---
    good_role_name = ctx.unique_name("role-goodtrust-")
    good_role = iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy("lambda.amazonaws.com")),
        Tags=[{"Key": "sim2real", "Value": "iam-trust-lambda-wrong-principal"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))
    iam.attach_role_policy(RoleName=good_role_name, PolicyArn=basic_exec_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=good_role_name, PolicyArn=basic_exec_policy_arn
        )
    )

    good_fn_name = ctx.unique_name("fn-goodtrust-")
    _create_function_with_retry(
        lam,
        FunctionName=good_fn_name,
        Runtime="python3.12",
        Role=good_role["Role"]["Arn"],
        Handler="index.handler",
        Code={"ZipFile": zip_bytes},
        Tags={"sim2real": "iam-trust-lambda-wrong-principal"},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_fn_name))
    final_state = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=good_fn_name)["State"],
        lambda state: state in ("Active", "Failed"),
        timeout_s=60,
        interval_s=2,
    )
    assert final_state == "Active", (
        f"control function with a correctly-trusting role never became Active: "
        f"{final_state}"
    )


def _trust_policy(service_principal: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _lambda_zip(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.py", handler_code)
    return buf.getvalue()


def _role_exists(iam, role_name: str) -> bool:
    try:
        iam.get_role(RoleName=role_name)
        return True
    except ClientError:
        return False


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) it raised. An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_function_with_retry(lam, *, timeout_s: float = 30.0, **kwargs):
    """Retry CreateFunction while the role's trust-policy update is still propagating.

    A role that legitimately trusts lambda.amazonaws.com can transiently draw the same
    InvalidParameterValueException as the broken role while IAM converges; only that
    specific message is retried, so a genuine rejection still raises immediately.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as e:
            error = e.response.get("Error", {})
            if (
                error.get("Code") == "InvalidParameterValueException"
                and "cannot be assumed" in error.get("Message", "")
                and time.monotonic() < deadline
            ):
                time.sleep(2)
                continue
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
