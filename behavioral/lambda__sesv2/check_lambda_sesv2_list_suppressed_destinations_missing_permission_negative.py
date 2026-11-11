"""lambda-sesv2-list-suppressed-destinations-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sesv2-list-suppressed-destinations-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sesv2"]

_HANDLER_CODE = '''
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        resp = client.list_suppressed_destinations(PageSize=50)
        addresses = [d["EmailAddress"] for d in resp.get("SuppressedDestinationSummaries", [])]
        return {
            "ok": True,
            "addresses": addresses,
            "has_field": "SuppressedDestinationSummaries" in resp,
        }
    except ClientError as e:
        return {"ok": False, "error_code": e.response["Error"]["Code"]}
'''


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without ses:ListSuppressedDestinations gets AccessDeniedException listing the
    suppression list; a role WITH it succeeds and sees the seeded entry when the account accepts one."""
    sesv2 = ctx.client("sesv2")
    email = f"{ctx.unique_name('sim2real-supp-list-')}@example.com"
    seeded = True
    # An SES-sandbox account rejects PutSuppressedDestination regardless of IAM.
    try:
        sesv2.put_suppressed_destination(EmailAddress=email, Reason="BOUNCE")
    except ClientError as e:
        err = e.response["Error"]
        assert err["Code"] == "BadRequestException", f"unexpected error seeding suppression entry: {err}"
        assert "sandbox" in err.get("Message", "").lower(), f"expected an SES-sandbox refusal, got: {err}"
        seeded = False
    else:

        def _cleanup_supp():
            try:
                sesv2.delete_suppressed_destination(EmailAddress=email)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NotFoundException":
                    raise

        ctx.on_cleanup(_cleanup_supp)

    # --- negative: role has no ses permissions at all ---
    denied_role_arn = _create_lambda_role(ctx, [])
    denied_fn = _create_lambda_function(ctx, denied_role_arn, _HANDLER_CODE)
    func_error, body = _invoke(ctx, denied_fn, {})
    assert func_error is None, f"lambda invocation errored unexpectedly: {func_error} {body}"
    assert body["ok"] is False, f"expected denied role's list call to fail, got: {body}"
    assert body["error_code"] == "AccessDeniedException", f"expected AccessDeniedException, got: {body}"

    # --- positive control: same handler code, role WITH the permission ---
    allowed_role_arn = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": ["ses:ListSuppressedDestinations"], "Resource": "*"}]
    )
    allowed_fn = _create_lambda_function(ctx, allowed_role_arn, _HANDLER_CODE)
    func_error2, body2 = _invoke(ctx, allowed_fn, {})
    assert func_error2 is None, f"lambda invocation errored: {func_error2} {body2}"
    assert body2["ok"] is True, f"list_suppressed_destinations call failed: {body2}"
    assert body2["has_field"] is True, (
        f"expected a real SuppressedDestinationSummaries field on the SES response, got: {body2}"
    )
    if seeded:
        assert email.lower() in [a.lower() for a in body2["addresses"]], (
            f"expected {email!r} in suppression list, got: {body2['addresses']}"
        )


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
