"""lambda-sesv2-get-identity-verification-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sesv2-get-identity-verification-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sesv2"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without ses:GetEmailIdentity gets AccessDeniedException checking verification
    status, even though the identity exists; granting the SAME role that SAME permission and
    re-invoking the IDENTICAL call flips it to success with the real verification status."""
    ses = ctx.client("sesv2")
    iam = ctx.client("iam")
    identity = ctx.unique_name("sim2real-lsesv2-verify-") + "@example.com"
    ses.create_email_identity(EmailIdentity=identity)
    ctx.on_cleanup(lambda: ses.delete_email_identity(EmailIdentity=identity))

    role_name, role_arn = _create_lambda_role(ctx, None)
    handler_src = """
import boto3
import botocore

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        resp = client.get_email_identity(EmailIdentity=event["identity"])
        return {"ok": True, "verified_for_sending": resp["VerifiedForSendingStatus"]}
    except botocore.exceptions.ClientError as err:
        return {"ok": False, "error_code": err.response["Error"]["Code"]}
"""
    function_name = _create_function(ctx, role_arn, handler_src)

    result = _invoke(ctx, function_name, {"identity": identity})
    assert result["function_error"] is None, f"lambda invocation raised: {result}"
    body = result["body"]
    assert body["ok"] is False, f"expected the ungranted role to be denied; got {body}"
    assert body["error_code"] == "AccessDeniedException", f"expected AccessDeniedException; got {body}"
    assert "verified_for_sending" not in body, f"a denied call must not leak verification status: {body}"

    # positive control: the caller's own permitted credentials can read the same identity
    info = ses.get_email_identity(EmailIdentity=identity)
    assert info["IdentityType"] == "EMAIL_ADDRESS"

    # restore: grant the SAME role the SAME permission and demand the IDENTICAL call now succeeds,
    # proving the earlier denial was caused by the missing grant and not by some other failure mode
    # that would deny the call regardless of permissions.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="grant-ses-get-email-identity",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "ses:GetEmailIdentity", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: _drop_role_policy(iam, role_name, "grant-ses-get-email-identity"))

    restored = _invoke_until_ok(ctx, function_name, {"identity": identity})
    restored_body = restored["body"]
    assert restored_body["ok"] is True, (
        f"granting ses:GetEmailIdentity to the SAME role must let the IDENTICAL call succeed; "
        f"got {restored_body}"
    )
    assert restored_body["verified_for_sending"] == info["VerifiedForSendingStatus"], (
        f"the now-permitted call must report the same verification status as the direct read; "
        f"got {restored_body} vs {info}"
    )


_PREFIX = "sim2real-lsesv2-"


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _lambda_trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _create_lambda_role(ctx: Any, inline_statements: list[dict] | None = None) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_lambda_trust_policy(),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    if inline_statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline-perms",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )

    def _cleanup() -> None:
        if inline_statements:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName="inline-perms")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_name, role_arn


def _drop_role_policy(iam: Any, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _zip_code(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_src)
    return buf.getvalue()


def _create_function(ctx: Any, role_arn: str, handler_src: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    code = _zip_code(handler_src)
    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code},
                Timeout=timeout,
                MemorySize=128,
                Tags={"sim2real": "true"},
            )
            break
        except botocore.exceptions.ClientError as err:
            err_code = err.response["Error"]["Code"]
            if err_code == "InvalidParameterValueException" and "role" in str(err).lower():
                last_err = err
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"role never became assumable by Lambda: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _invoke(ctx: Any, function_name: str, payload: dict | None = None) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps(payload or {}).encode("utf-8"),
    )
    body = json.loads(resp["Payload"].read())
    return {"function_error": resp.get("FunctionError"), "body": body}


def _invoke_until_ok(ctx: Any, function_name: str, payload: dict, timeout_s: int = 90, interval_s: int = 3) -> dict:
    """IAM policy grants are eventually consistent, so poll the identical invocation until it
    reflects the newly-granted permission rather than trusting a single sample."""
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        last = _invoke(ctx, function_name, payload)
        if last["function_error"] is None and last["body"].get("ok") is True:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"granting the permission never let the identical call succeed within {timeout_s}s: {last}")


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
