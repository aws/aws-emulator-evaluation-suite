"""lambda-sesv2-put-suppressed-destination-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sesv2-put-suppressed-destination-positive"
GROUP = "suppression-list"
SERVICES = ["lambda", "sesv2"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role granting ses:GetAccount and ses:PutSuppressedDestination clears IAM for both:
    GetAccount succeeds, and PutSuppressedDestination is refused by SES itself with a
    BadRequestException naming the sandbox, not by IAM with AccessDeniedException."""
    sesv2 = ctx.client("sesv2")
    address = f"{ctx.unique_name('sim2real-sesv2lam-supp-')}@example.com".lower()
    ctx.on_cleanup(lambda: _ignore(lambda: sesv2.delete_suppressed_destination(EmailAddress=address)))

    acct = sesv2.get_account()
    if acct.get("ProductionAccessEnabled"):
        raise AssertionError(
            "this account has SES production access, so PutSuppressedDestination is not refused by "
            "the sandbox gate here and the invariant under test (permission clears IAM but the write "
            "is still refused by the account-wide sandbox restriction) does not apply, so this check "
            "needs an account in the SES sandbox."
        )

    role_arn = _create_lambda_role(
        ctx,
        [
            {"Effect": "Allow", "Action": "ses:GetAccount", "Resource": "*"},
            {"Effect": "Allow", "Action": "ses:PutSuppressedDestination", "Resource": "*"},
        ],
    )
    code = '''
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("sesv2")
    account = client.get_account()
    try:
        client.put_suppressed_destination(EmailAddress=event["email"], Reason=event["reason"])
        put_error = None
    except ClientError as exc:
        put_error = {
            "code": exc.response["Error"]["Code"],
            "message": exc.response["Error"].get("Message") or "",
        }
    return {"production_access": account.get("ProductionAccessEnabled"), "put_error": put_error}
'''
    fn_name = _create_lambda_function(ctx, role_arn, code)
    body = _invoke_lambda(ctx, fn_name, {"email": address, "reason": "BOUNCE"})

    # Positive control: GetAccount cleared IAM and reached SES on the very same role, so the
    # rejection below cannot be explained away as "everything this role tries is denied".
    assert body["production_access"] is False, f"GetAccount must have reached SES and reported no production access, got {body}"
    assert body["put_error"] is not None, f"expected PutSuppressedDestination to be refused, got {body}"
    assert body["put_error"]["code"] == "BadRequestException", (
        f"a sandboxed PutSuppressedDestination must be refused by SES with BadRequestException (not an "
        f"IAM AccessDeniedException, which the role's grant already rules out), got {body['put_error']!r}"
    )
    expected_refusal = "Your account is still in the sandbox."
    assert body["put_error"]["message"] == expected_refusal, (
        f"the refusal must say why: {body['put_error']!r} != {expected_refusal!r}"
    )

    # Effect absent: the refused write must not have suppressed the address.
    code2, message2 = _error(lambda: sesv2.get_suppressed_destination(EmailAddress=address))
    assert code2 == "NotFoundException", f"a refused PutSuppressedDestination must leave {address!r} unsuppressed, got {code2!r}"
    expected_message2 = f"Email address {address} does not exist on your suppression list."
    assert message2 == expected_message2, f"{message2!r} != {expected_message2!r}"


# ===== helpers =====
def _ignore(fn):
    try:
        fn()
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


def _lambda_zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, inline_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sesv2lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_statements:
        policy_name = f"{role_name}-policy"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, role_arn, code):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-sesv2lam-fn-")
    zip_bytes = _lambda_zip_bytes(code)
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real"},
            )
            break
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, fn_name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name


def _invoke_lambda(ctx, fn_name, payload):
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation errored: {body}")
    return body


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates for a function on its first invocation and never
    deletes. Registered before the function's own teardown, so it runs after the function is
    gone; the service can still create the group from logs it delivers a few seconds later, so
    the group must stay absent across two consecutive reads 2 s apart. Only an already-absent group is
    tolerated; a group still present after 30 s raises."""
    import time

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    deadline = time.monotonic() + 30.0
    absent = 0
    while True:
        if absent == 0:
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        time.sleep(2.0)
        absent = 0 if present() else absent + 1
        if absent == 2:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
