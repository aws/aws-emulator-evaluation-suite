"""lambda-receipt-action-event-invocation-delivers-documented-ses-event."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-receipt-action-event-invocation-delivers-documented-ses-event"
GROUP = "e2e"
SERVICES = ["lambda", "ses"]

_RUNTIME = "python3.13"
_PROOF_KEY = "event.json"

_HANDLER_SOURCE = (
    "import json\n"
    "import os\n"
    "import boto3\n\n"
    "_s3 = boto3.client('s3')\n\n"
    "def handler(event, context):\n"
    "    _s3.put_object(\n"
    "        Bucket=os.environ['PROOF_BUCKET'],\n"
    "        Key=os.environ['PROOF_KEY'],\n"
    "        Body=json.dumps(event).encode('utf-8'),\n"
    "    )\n"
    "    return {'ok': True}\n"
)


def _zip_handler() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("handler.py", _HANDLER_SOURCE)
    return buffer.getvalue()


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last seen {last!r}")


def _receipt_rule_arn(region: str, account: str, rule_set: str, rule: str) -> str:
    """The SourceArn shape the SES Developer Guide publishes for the Lambda invoke grant.
    https://docs.aws.amazon.com/ses/latest/dg/receiving-email-permissions.html"""
    return f"arn:aws:ses:{region}:{account}:receipt-rule-set/{rule_set}:receipt-rule/{rule}"


def _receiving_domain(ctx, route53, sesv2) -> str:
    """The account's DNS baseline domain: the apex of its tagged public hosted zone, which
    SES has verified for sending (and so receives for)."""
    baseline_tag = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page["HostedZones"]:
            if zone["Config"].get("PrivateZone"):
                continue
            zone_id = zone["Id"].rsplit("/", 1)[-1]
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=zone_id
            )["ResourceTagSet"]["Tags"]
            if baseline_tag in zone_tags:
                domain = zone["Name"].rstrip(".")
                identity = sesv2.get_email_identity(EmailIdentity=domain)
                assert identity["VerifiedForSendingStatus"], (
                    f"the DNS baseline domain {domain!r} is not verified in {ctx.region}"
                )
                return domain
    raise AssertionError(
        "no public hosted zone carries the DNS baseline tag, so the account has no "
        "verified domain to receive mail for"
    )


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "requires:dns-baseline", "resource:account-singleton:ses-active-receipt-rule-set")
def run(ctx) -> None:
    """An Event LambdaAction invokes the function asynchronously with Records[].ses: mail
    carries the destination and Subject, receipt.action names the function and its invocation
    type, and every one of the five verdict objects carries a status.

    Reference: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-action-lambda.html
    Reference: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-notifications-contents.html
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    ses = ctx.client("ses")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    domain = _receiving_domain(ctx, route53, sesv2)

    bucket = ctx.unique_name("sim2real-ses-evt-")
    # us-east-1 refuses a LocationConstraint; every other region requires one.
    create = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    role_name = ctx.unique_name("sim2real-ses-evt-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
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
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "put-proof-object"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket}/{_PROOF_KEY}",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    function_name = ctx.unique_name("sim2real-ses-evt-fn-")
    created = _poll_until(
        lambda: _create_function(lam, function_name, role_arn, bucket),
        lambda r: r is not None,
        timeout_s=120,
        interval_s=5,
        description="Lambda accepts the freshly created execution role (IAM propagation)",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    function_arn = created["FunctionArn"]
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name).get("State"),
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {function_name} Active",
    )

    rule_set = ctx.unique_name("sim2real-ses-evt-rs-")
    rule_name = "lambda-event"
    lam.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-ses-invoke",
        Action="lambda:InvokeFunction",
        Principal="ses.amazonaws.com",
        SourceAccount=account,
        SourceArn=_receipt_rule_arn(ctx.region, account, rule_set, rule_name),
    )

    ses.create_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set))

    recipient = f"{ctx.unique_name('sim2real-in-')}@{domain}"
    _poll_call(
        lambda: ses.create_receipt_rule(
            RuleSetName=rule_set,
            Rule={
                "Name": rule_name,
                "Enabled": True,
                "ScanEnabled": False,
                "Recipients": [recipient],
                "Actions": [
                    {"LambdaAction": {"FunctionArn": function_arn, "InvocationType": "Event"}}
                ],
            },
        ),
        timeout_s=180,
        interval_s=10,
        description="CreateReceiptRule accepts the LambdaAction once the scoped invoke grant exists",
    )

    previous = ses.describe_active_receipt_rule_set().get("Metadata", {}).get("Name")
    ses.set_active_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(
        lambda: ses.set_active_receipt_rule_set(**({"RuleSetName": previous} if previous else {}))
    )

    described_action = ses.describe_receipt_rule(RuleSetName=rule_set, RuleName=rule_name)[
        "Rule"
    ]["Actions"][0]["LambdaAction"]
    assert described_action.get("InvocationType") == "Event", (
        f"an explicitly-Event LambdaAction must round-trip its invocation type, got "
        f"{described_action!r}"
    )

    sender = f"{ctx.unique_name('sim2real-')}@{domain}"
    token = ctx.unique_name("sim2real-token-")
    message_id = sesv2.send_email(
        FromEmailAddress=sender,
        Destination={"ToAddresses": [recipient]},
        Content={
            "Simple": {"Subject": {"Data": token}, "Body": {"Text": {"Data": "lambda event probe"}}}
        },
    )["MessageId"]

    body = _poll_until(
        lambda: _read_proof(s3, bucket),
        lambda b: b is not None,
        timeout_s=300,
        interval_s=2.0,
        description=f"the Lambda function's proof object for MessageId {message_id!r}",
    )
    event = json.loads(body)
    records = event["Records"]
    assert len(records) == 1, f"expected exactly one record, got {len(records)}: {records!r}"
    record = records[0]
    assert record["eventSource"] == "aws:ses", (
        f"expected eventSource 'aws:ses', got {record.get('eventSource')!r}"
    )

    mail = record["ses"]["mail"]
    assert recipient in mail["destination"], (
        f"mail.destination must list the recipient {recipient!r}, got {mail['destination']!r}"
    )
    assert mail["commonHeaders"]["subject"] == token, (
        f"mail.commonHeaders.subject must carry the probe token {token!r}, got "
        f"{mail['commonHeaders'].get('subject')!r}"
    )

    receipt = record["ses"]["receipt"]
    assert recipient in receipt["recipients"], (
        f"receipt.recipients must list the matched recipient {recipient!r}, got "
        f"{receipt['recipients']!r}"
    )
    action = receipt["action"]
    assert action["type"] == "Lambda", f"expected action.type 'Lambda', got {action!r}"
    assert action["functionArn"] == function_arn, (
        f"action.functionArn must name the invoked function {function_arn!r}, got {action!r}"
    )
    assert action.get("invocationType") == "Event", (
        f"action.invocationType must report the configured 'Event' invocation type, got {action!r}"
    )

    for verdict_name in ("spamVerdict", "virusVerdict", "spfVerdict", "dkimVerdict", "dmarcVerdict"):
        verdict = receipt.get(verdict_name)
        assert isinstance(verdict, dict) and "status" in verdict, (
            f"receipt.{verdict_name} must be an object carrying a status, got {verdict!r}"
        )


def _create_function(lam, function_name, role_arn, bucket):
    try:
        return lam.create_function(
            FunctionName=function_name,
            Runtime=_RUNTIME,
            Role=role_arn,
            Handler="handler.handler",
            Code={"ZipFile": _zip_handler()},
            Timeout=30,
            Environment={"Variables": {"PROOF_BUCKET": bucket, "PROOF_KEY": _PROOF_KEY}},
            Tags={"sim2real": CHECK},
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidParameterValueException":
            return None
        raise


def _poll_call(fn, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return fn()
        except ClientError as exc:
            last = exc.response.get("Error", {})
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not succeed within {timeout_s}s; last refusal {last!r}"
            )
        time.sleep(interval_s)


def _read_proof(s3, bucket):
    try:
        return s3.get_object(Bucket=bucket, Key=_PROOF_KEY)["Body"].read()
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("NoSuchKey",):
            return None
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
