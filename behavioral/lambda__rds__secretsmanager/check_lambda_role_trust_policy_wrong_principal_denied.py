"""lambda-role-trust-policy-wrong-principal-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-role-trust-policy-wrong-principal-denied"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER_CODE = """
def handler(event, context):
    return {"result": "ok"}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A role trusting ec2.amazonaws.com is refused by CreateFunction
    (InvalidParameterValueException) and sts:AssumeRole (AccessDenied), both with exact messages,
    and no function exists; a role trusting lambda.amazonaws.com creates a function that invokes."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    lam = ctx.client("lambda")

    # --- broken role: trusts ec2.amazonaws.com, not lambda.amazonaws.com ---
    ec2_role_name = ctx.unique_name("sim2real-lambda-trust-wrongsvc-")
    ec2_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    ec2_role = iam.create_role(
        RoleName=ec2_role_name,
        AssumeRolePolicyDocument=json.dumps(ec2_trust_policy),
        Tags=[{"Key": "sim2real", "Value": "lambda-role-trust-policy-wrong-principal-denied"}],
    )
    ec2_role_arn = ec2_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_role_name))

    ec2_function_name = ctx.unique_name("sim2real-lambda-trust-wrongsvc-fn-")
    zip_bytes = _make_lambda_zip(_HANDLER_CODE)

    code, message = _error_code(
        lambda: lam.create_function(
            FunctionName=ec2_function_name,
            Runtime="python3.12",
            Role=ec2_role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=15,
            MemorySize=128,
        )
    )
    assert code == "InvalidParameterValueException", f"{code!r}: {message!r}"
    assert message == "The role defined for the function cannot be assumed by Lambda.", message

    # effect absent: no function was created for the rejected role
    not_found_code, not_found_message = _error_code(
        lambda: lam.get_function(FunctionName=ec2_function_name)
    )
    assert not_found_code == "ResourceNotFoundException", f"{not_found_code!r}: {not_found_message!r}"
    ec2_function_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{ec2_function_name}"
    assert not_found_message == f"Function not found: {ec2_function_arn}", not_found_message

    # a service-principal-only trust policy is never directly assumable by an external
    # IAM caller regardless of which service is named -- this does not discriminate
    # ec2 vs lambda, it only confirms STS still enforces the trust policy on this path
    caller_arn = sts.get_caller_identity()["Arn"]
    assume_code, assume_message = _error_code(
        lambda: sts.assume_role(
            RoleArn=ec2_role_arn, RoleSessionName="sim2real-probe"
        )
    )
    assert assume_code == "AccessDenied", f"{assume_code!r}: {assume_message!r}"
    assert assume_message == (
        f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: {ec2_role_arn}"
    ), assume_message

    # --- positive control: role trusted by lambda.amazonaws.com succeeds ---
    good_role_name = ctx.unique_name("sim2real-lambda-trust-ok-ctrl2-")
    good_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    good_role = iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=json.dumps(good_trust_policy),
        Tags=[{"Key": "sim2real", "Value": "lambda-role-trust-policy-wrong-principal-denied"}],
    )
    good_role_arn = good_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))
    basic_exec_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=good_role_name, PolicyArn=basic_exec_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=good_role_name, PolicyArn=basic_exec_arn)
    )

    good_function_name = ctx.unique_name("sim2real-lambda-trust-ok-ctrl2-fn-")
    _create_function_with_retry(
        ctx,
        lam,
        FunctionName=good_function_name,
        Runtime="python3.12",
        Role=good_role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=15,
        MemorySize=128,
        Tags={"sim2real": "lambda-role-trust-policy-wrong-principal-denied"},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_function_name))
    _wait_function_active(ctx, lam, good_function_name)

    invoke_resp = lam.invoke(FunctionName=good_function_name, Payload=b"{}")
    assert invoke_resp["StatusCode"] == 200, invoke_resp
    assert "FunctionError" not in invoke_resp, invoke_resp
    payload = json.loads(invoke_resp["Payload"].read())
    assert payload == {"result": "ok"}, payload


def _make_lambda_zip(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises immediately,
    because an over-permissive target accepting what real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_function_with_retry(ctx, lam, timeout_s: float = 60.0, **kwargs: Any):
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
                time.sleep(3)
                continue
            raise
    assert last_err is not None, "retry loop exited with no captured ClientError"
    raise last_err


def _wait_function_active(ctx, lam, function_name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        if cfg["State"] == "Active":
            return
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg}")
        time.sleep(2)
    raise AssertionError(f"function {function_name} never became Active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
