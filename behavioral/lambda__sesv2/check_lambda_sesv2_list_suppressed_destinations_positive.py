"""lambda-sesv2-list-suppressed-destinations-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "lambda-sesv2-list-suppressed-destinations-positive"
GROUP = "suppression-list"
SERVICES = ["lambda", "sesv2"]


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda allowed ses:PutSuppressedDestination in an SES-sandbox account gets BadRequestException
    on the write, and its ListSuppressedDestinations call succeeds without the refused address."""
    sesv2 = ctx.client("sesv2")
    address = f"{ctx.unique_name('sim2real-sesv2lam-list-')}@example.com".lower()

    # positive control: an unpaginated list call succeeds on this account/credentials, so a
    # refusal below cannot be explained by broken creds or a dead sesv2 endpoint.
    control = sesv2.list_suppressed_destinations()
    assert "SuppressedDestinationSummaries" in control, control

    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["ses:PutSuppressedDestination", "ses:ListSuppressedDestinations"],
                "Resource": "*",
            }
        ],
    )
    code = '''
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        client.put_suppressed_destination(EmailAddress=event["address"], Reason="BOUNCE")
        put_error_code, put_message = None, None
    except ClientError as exc:
        put_error_code = exc.response["Error"]["Code"]
        put_message = exc.response["Error"]["Message"]

    addrs = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = client.list_suppressed_destinations(**kwargs)
        addrs.extend(s["EmailAddress"] for s in resp.get("SuppressedDestinationSummaries", []))
        token = resp.get("NextToken")
        if not token:
            break
    return {"put_error_code": put_error_code, "put_message": put_message, "addresses": addrs}
'''
    fn_name = _create_lambda_function(ctx, role_arn, code)
    body = _invoke_lambda(ctx, fn_name, {"address": address})

    # A sandbox account (no production access) refuses the put regardless of IAM.
    assert body["put_error_code"] == "BadRequestException", body
    assert "sandbox" in (body["put_message"] or "").lower(), body
    seen = {a.lower() for a in body["addresses"]}
    assert address not in seen, (
        f"expected {address} absent from the suppression list since its put was refused, got {seen}"
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
                Tags={"sim2real-check": CHECK},
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
    """Delete the log group Lambda creates on first invocation; it must stay absent across two reads
    5 s apart because logs delivered after the function is gone can recreate it. Raises if the
    group is still present after 30 s."""
    import time

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    deadline = time.monotonic() + 30.0
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        if not present():
            time.sleep(5.0)
            if not present():
                return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
