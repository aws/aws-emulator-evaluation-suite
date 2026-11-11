"""lambda-sesv2-create-email-identity-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sesv2-create-email-identity-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sesv2"]

_HANDLER_CREATE_IDENTITY = """
import boto3

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        client.create_email_identity(EmailIdentity=event["identity"])
        return {"success": True}
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        return {"success": False, "error_code": err.get("Code"), "error_message": err.get("Message", str(exc))}
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without ses:CreateEmailIdentity gets AccessDeniedException and the
    identity never appears in SES; an in-file role WITH the permission succeeds."""
    identity_bad = f"{ctx.unique_name('sim2real-ses-cid-bad-')}@example.com"
    identity_ok = f"{ctx.unique_name('sim2real-ses-cid-ok-')}@example.com"
    ctx.on_cleanup(lambda: _delete_identity_ignore(ctx, identity_ok))

    _, role_bad_arn = _create_role(ctx, [], "create-id-bad")
    _, role_ok_arn = _create_role(
        ctx, [{"Effect": "Allow", "Action": "ses:CreateEmailIdentity", "Resource": "*"}], "create-id-ok"
    )
    fn_bad = _create_function(ctx, role_bad_arn, _HANDLER_CREATE_IDENTITY, "create-id-bad")
    fn_ok = _create_function(ctx, role_ok_arn, _HANDLER_CREATE_IDENTITY, "create-id-ok")

    bad_body = _invoke(ctx, fn_bad, {"identity": identity_bad})
    assert bad_body["success"] is False, bad_body
    assert bad_body["error_code"] == "AccessDeniedException", bad_body
    expected_denial = _access_denied_message(
        ctx, role_bad_arn, fn_bad, "ses:CreateEmailIdentity", f"identity/{identity_bad}"
    )
    assert bad_body["error_message"] == expected_denial, f"{bad_body!r} != {expected_denial!r}"

    ses = ctx.client("sesv2")
    code, message = _error(lambda: ses.get_email_identity(EmailIdentity=identity_bad))
    assert code == "NotFoundException", code
    expected_message = f"Email identity <{identity_bad}> does not exist."
    assert message == expected_message, f"{message!r} != {expected_message!r}"

    ok_body = _invoke(ctx, fn_ok, {"identity": identity_ok})
    assert ok_body["success"] is True, ok_body
    got = ses.get_email_identity(EmailIdentity=identity_ok)
    assert got["IdentityType"] == "EMAIL_ADDRESS", got


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


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _access_denied_message(ctx, role_arn: str, function_name: str, action: str, resource: str) -> str:
    """The IAM denial SESv2 returns to a Lambda whose execution role has no grant for action."""
    role_name = role_arn.rsplit("/", 1)[-1]
    return (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{function_name} is not "
        f"authorized to perform: {action} on resource: "
        f"arn:aws:ses:{ctx.region}:{ctx.account}:{resource} "
        f"because no identity-based policy allows the {action} action"
    )


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
