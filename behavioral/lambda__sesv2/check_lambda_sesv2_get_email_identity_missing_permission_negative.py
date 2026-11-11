"""lambda-sesv2-get-email-identity-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sesv2-get-email-identity-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sesv2"]

_HANDLER_GET_IDENTITY = """
import boto3

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        resp = client.get_email_identity(EmailIdentity=event["identity"])
        return {"success": True, "identity_type": resp.get("IdentityType")}
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        return {"success": False, "error_code": err.get("Code"), "error_message": str(exc)}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without ses:GetEmailIdentity gets AccessDeniedException reading an
    identity's attributes; an in-file role WITH the permission reads them successfully."""
    identity = f"{ctx.unique_name('sim2real-ses-get-')}@example.com"
    ses = ctx.client("sesv2")
    ses.create_email_identity(EmailIdentity=identity)
    ctx.on_cleanup(lambda: _delete_identity_ignore(ctx, identity))

    _, role_bad_arn = _create_role(ctx, [], "get-id-bad")
    _, role_ok_arn = _create_role(
        ctx, [{"Effect": "Allow", "Action": "ses:GetEmailIdentity", "Resource": "*"}], "get-id-ok"
    )
    fn_bad = _create_function(ctx, role_bad_arn, _HANDLER_GET_IDENTITY, "get-id-bad")
    fn_ok = _create_function(ctx, role_ok_arn, _HANDLER_GET_IDENTITY, "get-id-ok")

    bad_body = _invoke(ctx, fn_bad, {"identity": identity})
    assert bad_body["success"] is False, bad_body
    assert bad_body["error_code"] == "AccessDeniedException", bad_body
    assert "GetEmailIdentity" in bad_body.get("error_message", ""), bad_body

    ok_body = _invoke(ctx, fn_ok, {"identity": identity})
    assert ok_body["success"] is True, ok_body
    assert ok_body["identity_type"] == "EMAIL_ADDRESS", ok_body


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


def _delete_identity_ignore(ctx, identity):
    try:
        ctx.client("sesv2").delete_email_identity(EmailIdentity=identity)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
                Tags={"sim2real": "true"},
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
