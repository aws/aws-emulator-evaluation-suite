"""lambda-sesv2-put-suppressed-destination-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sesv2-put-suppressed-destination-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sesv2"]

_CODE = '''
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        client.put_suppressed_destination(EmailAddress=event["email"], Reason=event["reason"])
    except ClientError as exc:
        return {
            "success": False,
            "error_code": exc.response["Error"]["Code"],
            "message": exc.response["Error"].get("Message") or "",
        }
    return {"success": True}
'''


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role lacking ses:PutSuppressedDestination is denied by IAM (AccessDeniedException),
    while a sibling role with it reaches SES and is refused by the sandbox (BadRequestException):
    two distinct errors from two layers show IAM is enforced before the SES sandbox gate."""
    sesv2 = ctx.client("sesv2")
    acct = sesv2.get_account()
    if acct.get("ProductionAccessEnabled"):
        raise AssertionError(
            "this account has SES production access, so PutSuppressedDestination is not refused by "
            "the sandbox gate here and the invariant under test (permission reaches SES but is still "
            "refused by the account-wide sandbox restriction) does not apply, so this check needs an "
            "account in the SES sandbox."
        )

    denied_address = f"{ctx.unique_name('sim2real-sesv2lam-supp-denied-')}@example.com".lower()
    allowed_address = f"{ctx.unique_name('sim2real-sesv2lam-supp-allowed-')}@example.com".lower()
    ctx.on_cleanup(lambda: _ignore(lambda: sesv2.delete_suppressed_destination(EmailAddress=denied_address)))
    ctx.on_cleanup(lambda: _ignore(lambda: sesv2.delete_suppressed_destination(EmailAddress=allowed_address)))

    # Role with NO permissions at all -> the sesv2 call inside the function is denied by IAM,
    # before it ever reaches SES.
    role_no_perm = _create_lambda_role(ctx, None)
    fn_no_perm = _create_lambda_function(ctx, role_no_perm, _CODE)
    body = _invoke_lambda(ctx, fn_no_perm, {"email": denied_address, "reason": "BOUNCE"})
    assert body["success"] is False, body
    assert body["error_code"] == "AccessDeniedException", body
    expected_denial = _access_denied_message(
        ctx, role_no_perm, fn_no_perm, "ses:PutSuppressedDestination", "*"
    )
    assert body["message"] == expected_denial, f"{body!r} != {expected_denial!r}"

    # Effect absent: the address was never suppressed.
    code, message = _error(lambda: sesv2.get_suppressed_destination(EmailAddress=denied_address))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    expected_message = f"Email address {denied_address} does not exist on your suppression list."
    assert message == expected_message, f"{message!r} != {expected_message!r}"

    # Positive control: a role WITH the permission clears IAM (so the request reaches SES) but is
    # still refused there, by a different and more specific error than the IAM denial above.
    role_with_perm = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": "ses:PutSuppressedDestination", "Resource": "*"}]
    )
    fn_with_perm = _create_lambda_function(ctx, role_with_perm, _CODE)
    control_body = _invoke_lambda(ctx, fn_with_perm, {"email": allowed_address, "reason": "COMPLAINT"})
    assert control_body["success"] is False, control_body
    assert control_body["error_code"] == "BadRequestException", control_body
    assert control_body["error_code"] != body["error_code"], (
        f"the permitted and denied roles must fail for different reasons, both got {body['error_code']!r}"
    )
    expected_refusal = "Your account is still in the sandbox."
    assert control_body["message"] == expected_refusal, f"{control_body!r} != {expected_refusal!r}"

    # Effect absent: the permitted-but-sandboxed write never suppressed the address either.
    code2, message2 = _error(lambda: sesv2.get_suppressed_destination(EmailAddress=allowed_address))
    assert code2 == "NotFoundException", f"expected NotFoundException, got {code2!r}"
    expected_message2 = f"Email address {allowed_address} does not exist on your suppression list."
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


def _access_denied_message(ctx, role_arn: str, function_name: str, action: str, resource: str) -> str:
    """The IAM denial SESv2 returns to a Lambda whose execution role has no grant for action
    on resource (the resource exactly as SESv2 names it in the denial)."""
    role_name = role_arn.rsplit("/", 1)[-1]
    return (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{function_name} is not "
        f"authorized to perform: {action} on resource: {resource} "
        f"because no identity-based policy allows the {action} action"
    )


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
