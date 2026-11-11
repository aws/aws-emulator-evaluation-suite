"""lambda-wrong-trust-policy-sesv2-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-wrong-trust-policy-sesv2-negative"
GROUP = "iam-trust"
SERVICES = ["lambda", "sesv2"]

_HANDLER_GET_ACCOUNT = """
import boto3

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        resp = client.get_account()
        return {"success": True, "sending_enabled": resp.get("SendingEnabled")}
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        return {"success": False, "error_code": err.get("Code"), "error_message": str(exc)}
"""

_WRONG_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateFunction refuses a role not trusting lambda.amazonaws.com
    (InvalidParameterValueException, exact message) and no function exists, while a correctly
    trusted role's function gets a SendingEnabled field from sesv2 GetAccount."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    bad_role_name = ctx.unique_name("sim2real-badtrust-")
    iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=_WRONG_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, bad_role_name))
    bad_role_arn = iam.get_role(RoleName=bad_role_name)["Role"]["Arn"]

    fn_bad_name = ctx.unique_name("sim2real-badtrust-fn-")
    zip_bytes = _make_zip(_HANDLER_GET_ACCOUNT)

    try:
        ctx.on_cleanup(lambda _n=fn_bad_name: _delete_lambda_log_group(ctx, _n))
        lam.create_function(
            FunctionName=fn_bad_name,
            Runtime="python3.12",
            Role=bad_role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=30,
            Publish=True,
            Tags={"sim2real": CHECK},
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
    else:
        # A real-AWS acceptance here is the strongest signal available.
        ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_bad_name))
        raise AssertionError(
            f"create_function({fn_bad_name}) unexpectedly SUCCEEDED with a role whose trust "
            "policy trusts ec2.amazonaws.com instead of lambda.amazonaws.com"
        )
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code}"
    expected_message = "The role defined for the function cannot be assumed by Lambda."
    assert message == expected_message, f"{message!r} != {expected_message!r}"

    absent_code, absent_message = _error(lambda: lam.get_function(FunctionName=fn_bad_name))
    assert absent_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {absent_code}"
    expected_absent = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_bad_name}"
    )
    assert absent_message == expected_absent, f"{absent_message!r} != {expected_absent!r}"

    _, role_ok_arn = _create_role(
        ctx, [{"Effect": "Allow", "Action": "ses:GetAccount", "Resource": "*"}], "goodtrust"
    )
    fn_ok = _create_function(ctx, role_ok_arn, _HANDLER_GET_ACCOUNT, "goodtrust")
    ok_body = _invoke(ctx, fn_ok, {})
    assert ok_body["success"] is True, ok_body
    assert "sending_enabled" in ok_body, ok_body


_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_LOGS_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
    }
)


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _make_zip(handler_source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_source)
    return buf.getvalue()


def _create_role(ctx, statements, hint):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-{hint}-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="logs", PolicyDocument=_LOGS_POLICY)
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="grant",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_name, role_arn


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    for policy_name in ("logs", "grant"):
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_function(ctx, role_arn, handler_source, hint, timeout=30):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name(f"sim2real-{hint}-")
    zip_bytes = _make_zip(handler_source)
    deadline = time.monotonic() + 60
    while True:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Publish=True,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_active(ctx, fn_name)
    return fn_name


def _wait_active(ctx, fn_name, timeout_s=90):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=fn_name)
        state = cfg["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function failed to activate: {cfg.get('StateReasonCode')}")
        time.sleep(2)
    raise AssertionError(f"function {fn_name} never became Active")


def _invoke(ctx, fn_name, payload):
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(payload).encode("utf-8"))
    return json.loads(resp["Payload"].read())


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
