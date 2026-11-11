"""lambda-sesv2-delete-suppressed-destination-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sesv2-delete-suppressed-destination-positive"
GROUP = "sdk-invocation"
SERVICES = ["lambda", "sesv2"]

_HANDLER_CODE = '''
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        client.delete_suppressed_destination(EmailAddress=event["email"])
        return {"ok": True}
    except ClientError as e:
        return {
            "ok": False,
            "error_code": e.response["Error"]["Code"],
            "error_message": e.response["Error"].get("Message", ""),
        }
'''


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """In the SES sandbox PutSuppressedDestination is refused and creates nothing; a Lambda
    scoped to ses:DeleteSuppressedDestination then gets the exact NotFoundException deleting it.
    """
    # A successful put means the account left the sandbox; the check then fails rather than
    # silently exercising a different flow.
    sesv2 = ctx.client("sesv2")
    email = f"{ctx.unique_name('sim2real-supp-del-')}@example.com"
    not_found_message = f"Email address {email} does not exist on your suppression list."

    # positive control: sesv2 is reachable and not globally denied -- an address that was
    # never suppressed is correctly reported absent.
    pre_code, pre_message = _error(lambda: sesv2.get_suppressed_destination(EmailAddress=email))
    assert pre_code == "NotFoundException", f"expected NotFoundException before any put, got {pre_code!r}"
    assert pre_message == not_found_message, f"{pre_message!r} != {not_found_message!r}"

    try:
        sesv2.put_suppressed_destination(EmailAddress=email, Reason="COMPLAINT")
    except ClientError as err:
        assert _is_sandbox_block(err), f"expected the SES sandbox refusal, got {err.response['Error']}"
    else:
        ctx.on_cleanup(lambda: _ignore(lambda: sesv2.delete_suppressed_destination(EmailAddress=email)))
        raise AssertionError(
            "PutSuppressedDestination unexpectedly succeeded -- this account has left the SES "
            "sandbox, so the entitlement-gate contract this check asserts no longer holds here."
        )

    # effect-absent: the refused put created nothing.
    absent_code, absent_message = _error(lambda: sesv2.get_suppressed_destination(EmailAddress=email))
    assert absent_code == "NotFoundException", f"expected the refused put to create nothing, got {absent_code!r}"
    assert absent_message == not_found_message, f"{absent_message!r} != {not_found_message!r}"

    role_arn = _create_lambda_role(
        ctx,
        [{"Effect": "Allow", "Action": ["ses:DeleteSuppressedDestination"], "Resource": "*"}],
    )
    fn_name = _create_lambda_function(ctx, role_arn, _HANDLER_CODE)

    func_error, body = _invoke(ctx, fn_name, {"email": email})
    assert func_error is None, f"lambda invocation errored: {func_error} {body}"
    assert body["ok"] is False, f"delete_suppressed_destination unexpectedly succeeded: {body}"
    assert body["error_code"] == "NotFoundException", f"expected NotFoundException from the IAM-scoped delete, got {body}"
    assert body["error_message"] == not_found_message, f"{body!r} != {not_found_message!r}"

    # terminal read: independent of the lambda's own call, still absent at the destination.
    code, message = _error(lambda: sesv2.get_suppressed_destination(EmailAddress=email))
    assert code == "NotFoundException", f"expected NotFoundException for the never-created suppression, got {code!r}"
    assert message == not_found_message, f"{message!r} != {not_found_message!r}"


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _is_sandbox_block(err: ClientError) -> bool:
    error = err.response.get("Error", {})
    return error.get("Code") == "BadRequestException" and "sandbox" in error.get("Message", "").lower()


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, ses_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sesv2lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))

    if ses_statements:
        policy_name = ctx.unique_name("sim2real-sesv2lambda-policy-")
        policy_doc = {"Version": "2012-10-17", "Statement": ses_statements}
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, role_arn, code):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-sesv2lambda-fn-")
    zip_bytes = _zip_code(code)
    deadline = time.monotonic() + 90
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real": "true"},
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"could not create lambda function, last error: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(ctx, name)
    return name


def _wait_active(ctx, name, timeout_s=120.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"lambda function {name} entered Failed state")
        time.sleep(2)
    raise AssertionError(f"lambda function {name} did not become Active within {timeout_s}s")


def _invoke(ctx, name, payload):
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    return resp.get("FunctionError"), body


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
