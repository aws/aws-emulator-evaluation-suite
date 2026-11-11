"""lambda-sesv2-send-templated-email-positive."""

from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sesv2-send-templated-email-positive"
GROUP = "sdk-invocation"
SERVICES = ["lambda", "sesv2"]

_HANDLER_CODE = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        resp = client.send_email(
            FromEmailAddress=event["from_address"],
            Destination={"ToAddresses": [event["to_address"]]},
            Content={
                "Template": {
                    "TemplateName": event["template_name"],
                    "TemplateData": event["template_data"],
                }
            },
            ConfigurationSetName=event["configuration_set"],
        )
        return {"ok": True, "message_id": resp["MessageId"]}
    except ClientError as e:
        return {"ok": False, "error_code": e.response["Error"]["Code"]}
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
)
def run(ctx) -> None:
    """A Lambda sending a stored SES template (Content.Template) gets a MessageId, and the
    configuration set's SNS->SQS destination receives that message's Delivery event carrying the
    rendered template subject, so SES rendered and delivered the template."""
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    from_address = f"{ctx.unique_name('sim2real-test-')}@{_dns_baseline_domain(ctx, route53, sesv2)}"
    config_set, queue_url = _event_witness(ctx, sesv2, sns, sqs, ["DELIVERY"])

    template_name = ctx.unique_name("sim2real-sesv2-template-")
    sesv2.create_email_template(
        TemplateName=template_name,
        TemplateContent={
            "Subject": "sim2real templated test {{name}}",
            "Text": "Hello {{name}}, this is a sim2real behavioral check.",
        },
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: sesv2.delete_email_template(TemplateName=template_name))

    role_arn = _create_lambda_role(
        ctx,
        [{"Effect": "Allow", "Action": ["ses:SendEmail", "ses:SendTemplatedEmail"], "Resource": "*"}],
    )
    fn_name = _create_lambda_function(ctx, role_arn, _HANDLER_CODE)

    # The role's inline SES policy can be invisible to the function for a short while after it is
    # attached; retry only that AccessDenied, bounded.
    left = ctx.time_left()
    deadline = time.monotonic() + (90.0 if left is None else max(1.0, min(90.0, left - 5.0)))
    while True:
        func_error, body = _invoke(
            ctx,
            fn_name,
            {
                "from_address": from_address,
                "to_address": "success@simulator.amazonses.com",
                "template_name": template_name,
                "template_data": json.dumps({"name": "sim2real"}),
                "configuration_set": config_set,
            },
        )
        if body.get("error_code") != "AccessDeniedException" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert func_error is None, f"lambda invocation errored: {func_error} {body}"
    assert body["ok"] is True, f"send_email call failed: {body}"
    message_id = body["message_id"]
    assert isinstance(message_id, str) and len(message_id) > 0, (
        f"expected a non-empty string MessageId, got {message_id!r}"
    )

    # Independent read at the destination: the Delivery event SES publishes for this MessageId
    # carries the *rendered* template subject, not just a SendEmail call reporting success.
    delivery = _events_for(sqs, queue_url, "Delivery", [message_id], timeout_s=300)[message_id]
    assert delivery["delivery"]["recipients"] == ["success@simulator.amazonses.com"], (
        f"the Delivery event names recipients {delivery['delivery']['recipients']!r}"
    )
    expected_subject = "sim2real templated test sim2real"
    subject = delivery["mail"]["commonHeaders"]["subject"]
    assert subject == expected_subject, (
        f"expected the rendered template subject {expected_subject!r}, got {subject!r}"
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


def _event_witness(ctx, sesv2, sns, sqs, event_types):
    """A configuration set whose event destination publishes ``event_types`` to an SNS topic
    delivering raw to an SQS queue: ``(configuration set name, queue url)``."""
    base = ctx.unique_name("sim2real-xsvc-ses-wit-")
    topic_arn = sns.create_topic(Name=base)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(QueueName=base)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                        }
                    ],
                }
            )
        },
    )
    sub = sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"},
        ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))
    sesv2.create_configuration_set(ConfigurationSetName=base)
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=base))
    sesv2.create_configuration_set_event_destination(
        ConfigurationSetName=base,
        EventDestinationName="sim2real-dest",
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": event_types,
            "SnsDestination": {"TopicArn": topic_arn},
        },
    )
    return base, queue_url


def _events_for(sqs, queue_url, event_type, message_ids, timeout_s):
    """``{messageId: event}`` of the ``event_type`` events published for ``message_ids``; FAILS
    naming the ids still missing at the deadline."""
    deadline = time.monotonic() + timeout_s
    seen: dict[str, dict] = {}
    while time.monotonic() < deadline and not set(message_ids) <= set(seen):
        for m in sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            try:
                event = json.loads(m["Body"])
            except ValueError:
                continue
            if isinstance(event, dict) and event.get("eventType") == event_type:
                seen.setdefault(event["mail"]["messageId"], event)
    missing = set(message_ids) - set(seen)
    assert not missing, f"{event_type} events for {sorted(missing)} never arrived in {timeout_s}s"
    return seen


# ===== end helpers =====


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_policy_arn = (
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    )

    if ses_statements:
        policy_name = ctx.unique_name("sim2real-sesv2lambda-policy-")
        policy_doc = {"Version": "2012-10-17", "Statement": ses_statements}
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_doc),
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
    return role_arn


def _create_lambda_function(ctx, role_arn, code):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-sesv2lambda-fn-")
    zip_bytes = _zip_code(code)
    deadline = time.monotonic() + 90
    last_err = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(
            f"could not create lambda function, last error: {last_err}"
        )
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, name))
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
    raise AssertionError(
        f"lambda function {name} did not become Active within {timeout_s}s"
    )


def _invoke(ctx, name, payload):
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    return resp.get("FunctionError"), body


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
