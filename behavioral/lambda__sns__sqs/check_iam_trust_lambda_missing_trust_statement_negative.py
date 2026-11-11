"""iam-trust-lambda-missing-trust-statement-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-trust-lambda-missing-trust-statement-negative"
GROUP = "iam-trust"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateFunction refuses a role trusting only ec2.amazonaws.com, not lambda.amazonaws.com
    (InvalidParameterValueException, exact message) and no function exists, while a role trusting
    lambda.amazonaws.com creates a function that invokes."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    code = _lambda_zip_bytes("def handler(event, context):\n    return event\n")

    # --- broken: role trusts ec2.amazonaws.com, not lambda.amazonaws.com ---
    _bad_role_name, bad_role_arn = _create_role(
        ctx,
        iam,
        trust_principals=["ec2.amazonaws.com"],
        managed_policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
    )
    bad_func_name = ctx.unique_name("sim2real-iamtrust-bad-")
    ctx.on_cleanup(lambda: _delete_function_if_exists(lam, bad_func_name))

    err_code, err_message = _client_error(lambda: lam.create_function(
        FunctionName=bad_func_name,
        Runtime="python3.12",
        Role=bad_role_arn,
        Handler="index.handler",
        Code={"ZipFile": code},
        Timeout=15,
    ))
    assert err_code == "InvalidParameterValueException", err_code
    assert err_message == "The role defined for the function cannot be assumed by Lambda.", err_message

    not_found_code, not_found_message = _client_error(lambda: lam.get_function(FunctionName=bad_func_name))
    assert not_found_code == "ResourceNotFoundException", not_found_code
    expected = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_func_name}"
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"

    # --- positive control: role trusts lambda.amazonaws.com correctly ---
    _good_role_name, good_role_arn = _create_role(
        ctx,
        iam,
        trust_principals=["lambda.amazonaws.com"],
        managed_policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
    )
    good_func_name = ctx.unique_name("sim2real-iamtrust-good-")
    _create_function_with_retry(
        lam,
        FunctionName=good_func_name,
        Runtime="python3.12",
        Role=good_role_arn,
        Handler="index.handler",
        Code={"ZipFile": code},
        Timeout=15,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_func_name))
    _wait_for_function_active(lam, good_func_name)
    invoke = lam.invoke(FunctionName=good_func_name, Payload=b"{}")
    assert invoke.get("FunctionError") is None, invoke.get("FunctionError")


def _create_role(ctx, iam, trust_principals, managed_policy_arns=None, inline_policy=None):
    role_name = ctx.unique_name("sim2real-iamtrust-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": p}, "Action": "sts:AssumeRole"}
            for p in trust_principals
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_doc))
    role_arn = resp["Role"]["Arn"]
    attached: list[str] = []
    for policy_arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        attached.append(policy_arn)
    inline_name = None
    if inline_policy:
        inline_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name, PolicyName=inline_name, PolicyDocument=json.dumps(inline_policy)
        )

    def _cleanup():
        if inline_name:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=inline_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for pa in attached:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pa)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_name, role_arn


def _lambda_zip_bytes(handler_body: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_body)
    return buf.getvalue()


def _client_error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as e:
        error = e.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _delete_function_if_exists(lam, func_name):
    try:
        lam.delete_function(FunctionName=func_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_function_with_retry(lam, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    assert last_err is not None, "create_function retry loop exited with no captured error"
    raise last_err


def _wait_for_function_active(lam, func_name, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=func_name)["State"]
        if state == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"function {func_name} never became Active")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
