"""lambda-sesv2-wrong-region-endpoint-negative."""

from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sesv2-wrong-region-endpoint-negative"
GROUP = "arn-resolution"
SERVICES = ["lambda", "sesv2"]

_HANDLER_SRC = """
import boto3
import botocore

def handler(event, context):
    client = boto3.client("sesv2", region_name=event["region"])
    try:
        resp = client.send_email(
            FromEmailAddress=event["source"],
            Destination={"ToAddresses": [event["to"]]},
            Content={
                "Simple": {
                    "Subject": {"Data": "sim2real cross-region check"},
                    "Body": {"Text": {"Data": "hello"}},
                }
            },
        )
        return {"sent": True, "message_id": resp["MessageId"]}
    except botocore.exceptions.ClientError as err:
        return {"sent": False, "error_code": err.response["Error"]["Code"]}
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data", "requires:dns-baseline")
def run(ctx) -> None:
    """An sesv2 client pointed at a region where the sender identity is unverified must not silently deliver cross-region."""
    role_arn = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": "ses:SendEmail", "Resource": "*"}]
    )
    function_name = _create_function(ctx, role_arn, _HANDLER_SRC)
    sender = _verified_sender(ctx)
    home_region = ctx.region
    # us-west-2 / us-east-1 are not resource pins: SES identity verification is itself
    # region-scoped, so the *other* region is the actual subject under test.
    other_region = "us-west-2" if home_region != "us-west-2" else "us-east-1"

    # positive control: sending from the region where the identity is actually verified works
    control = _invoke(
        ctx,
        function_name,
        {
            "region": home_region,
            "source": sender,
            "to": "success@simulator.amazonses.com",
        },
    )
    assert control["function_error"] is None, f"lambda invocation raised: {control}"
    assert control["body"]["sent"] is True, (
        f"expected send from {home_region} (verified) to succeed, got {control['body']}"
    )

    # negative: the identical identity, used from a region it was never verified in, must be rejected
    result = _invoke(
        ctx,
        function_name,
        {
            "region": other_region,
            "source": sender,
            "to": "success@simulator.amazonses.com",
        },
    )
    assert result["function_error"] is None, f"lambda invocation raised: {result}"
    body = result["body"]
    assert body["sent"] is False, (
        f"expected send from {other_region} (unverified) to be rejected, got {body}"
    )
    assert body["error_code"] == "MessageRejected", (
        f"expected MessageRejected, got {body}"
    )


# ===== helpers =====
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


def _create_lambda_role(ctx: Any, inline_statements: list[dict] | None = None) -> str:
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
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": inline_statements}
            ),
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
    return role_arn


def _zip_code(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_src)
    return buf.getvalue()


def _create_function(
    ctx: Any, role_arn: str, handler_src: str, timeout: int = 30
) -> str:
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    code = _zip_code(handler_src)
    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
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
            if (
                err_code == "InvalidParameterValueException"
                and "role" in str(err).lower()
            ):
                last_err = err
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"role never became assumable by Lambda: {last_err}")
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, name))
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


def _verified_sender(ctx: Any) -> str:
    """An address under the target's verified sending domain (_sending_domain)."""
    domain = _sending_domain(ctx, ctx.client("route53"), ctx.client("sesv2"))
    return f"{ctx.unique_name('sim2real-ses-sender-')}@{domain}"


_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}


def _sending_domain(ctx, route53, sesv2):
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
