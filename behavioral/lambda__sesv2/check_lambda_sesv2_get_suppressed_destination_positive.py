"""lambda-sesv2-get-suppressed-destination-positive."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sesv2-get-suppressed-destination-positive"
GROUP = "suppression-list"
SERVICES = ["lambda", "sesv2"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:representation",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
    "resource:account-singleton:ses-account",
)
def run(ctx) -> None:
    """A Lambda whose role grants ses:GetSuppressedDestination retrieves the BOUNCE reason of a
    destination a hard bounce put on the account suppression list (the sandbox refuses
    PutSuppressedDestination, so a bounce is the way every account creates one)."""
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    domain = _dns_baseline_domain(ctx, route53, sesv2)

    original_reasons = sesv2.get_account()["SuppressionAttributes"]["SuppressedReasons"]
    ctx.on_cleanup(
        lambda: sesv2.put_account_suppression_attributes(SuppressedReasons=original_reasons)
    )
    sesv2.put_account_suppression_attributes(SuppressedReasons=["BOUNCE", "COMPLAINT"])

    # Any simulator.amazonses.com address that is not a documented alias hard-bounces as an
    # unknown user; unique per run so no sibling races this entry.
    address = f"{ctx.unique_name('sim2real-sesv2lam-get-')}@simulator.amazonses.com".lower()
    message_id = sesv2.send_email(
        FromEmailAddress=f"{ctx.unique_name('sim2real-')}@{domain}",
        Destination={"ToAddresses": [address]},
        Content={"Simple": {"Subject": {"Data": f"sim2real {CHECK}"}, "Body": {"Text": {"Data": "x"}}}},
    )["MessageId"]
    ctx.on_cleanup(lambda: _delete_suppressed_destination(sesv2, address))
    _wait_suppressed(sesv2, address, timeout_s=180.0)

    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": "ses:GetSuppressedDestination",
                "Resource": "*",
            }
        ],
    )
    code = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        resp = client.get_suppressed_destination(EmailAddress=event["email"])
    except ClientError as exc:
        return {"success": False, "error_code": exc.response["Error"]["Code"]}
    dest = resp["SuppressedDestination"]
    return {
        "success": True,
        "email": dest["EmailAddress"],
        "reason": dest["Reason"],
        "message_id": dest["Attributes"]["MessageId"],
    }
"""
    fn_name = _create_lambda_function(ctx, role_arn, code)
    body = _invoke_lambda(ctx, fn_name, {"email": address})

    assert body["success"] is True, body
    assert body["email"].lower() == address, (
        f"expected email={address!r}, got {body['email']!r}"
    )
    assert body["reason"] == "BOUNCE", (
        f"expected reason='BOUNCE', got {body['reason']!r}"
    )
    assert body["message_id"] == message_id, (
        f"the entry names MessageId {body['message_id']!r}, not the bounced send's {message_id!r}"
    )


# ===== helpers =====
_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}


def _dns_baseline_domain(ctx, route53, sesv2):
    """The target's DNS baseline domain (its tagged public hosted zone, verified in SES); an account without one fails the check."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for z in page["HostedZones"]:
            if z["Config"].get("PrivateZone"):
                continue
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=z["Id"].rsplit("/", 1)[-1]
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                domain = z["Name"].rstrip(".")
                identity = sesv2.get_email_identity(EmailIdentity=domain)
                assert identity["VerifiedForSendingStatus"], (
                    f"the DNS baseline domain {domain!r} is not verified for sending in {ctx.region}"
                )
                return domain
    raise AssertionError(
        "this account has no DNS baseline zone (a public hosted zone carrying the baseline "
        "tag, verified in SES) and so no sending domain; the check requires one"
    )


def _delete_suppressed_destination(sesv2, address):
    """Remove ``address`` from the account suppression list; already absent is fine."""
    try:
        sesv2.delete_suppressed_destination(EmailAddress=address)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _wait_suppressed(sesv2, address, *, timeout_s):
    """Poll until the hard bounce has put ``address`` on the account suppression list."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sesv2.get_suppressed_destination(EmailAddress=address)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NotFoundException":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{address!r} never appeared on the account suppression list within {timeout_s}s "
                "after a hard bounce"
            )
        time.sleep(5)


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
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_statements:
        policy_name = f"{role_name}-policy"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": inline_statements}
            ),
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
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
                Tags={"sim2real:managed": "true"},
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
