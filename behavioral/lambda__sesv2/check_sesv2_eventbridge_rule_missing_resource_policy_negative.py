"""sesv2-eventbridge-rule-missing-resource-policy-negative."""

from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "sesv2-eventbridge-rule-missing-resource-policy-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sesv2"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "requires:dns-baseline")
def run(ctx) -> None:
    """An EventBridge rule whose Lambda target lacks a lambda:InvokeFunction grant for
    events.amazonaws.com never invokes it on a matching SESv2 Send event; granting the permission
    on the same rule and target then yields an invocation, so only the grant was missing."""
    from_address = _ensure_verified_sender_identity(ctx)
    queue_url, queue_arn = _create_relay_queue(ctx)
    role_arn = _create_relay_role(ctx, queue_arn)
    lambda_arn, function_name = _create_relay_lambda(ctx, role_arn, queue_url)

    config_set_name = _create_config_set_with_eventbridge(ctx, ["SEND"])
    rule_name, rule_arn = _create_rule(
        ctx, {"source": ["aws.ses"], "detail-type": ["Email Sent"]}
    )
    _put_lambda_target(ctx, rule_name, lambda_arn)
    # Deliberately DO NOT call add_permission: the rule can match, but EventBridge has no
    # resource-based permission to invoke this function.

    to_address = "success@simulator.amazonses.com"
    _send_probe_email(
        ctx, config_set_name, from_address, to_address, "sim2real no-permission probe"
    )

    # Effect must be absent: generous bounded poll finds zero relayed events.
    no_permission_events = _drain_for(ctx, queue_url, timeout_s=75.0)
    assert no_permission_events == [], (
        f"Lambda was invoked without an EventBridge invoke permission: {no_permission_events!r}"
    )

    # Positive control: grant the permission on the SAME rule/target, resend, confirm delivery.
    _allow_eventbridge_invoke(ctx, function_name, rule_arn)
    _send_probe_email(
        ctx, config_set_name, from_address, to_address, "sim2real with-permission probe"
    )
    events_seen = _wait_for_relay_events(ctx, queue_url, min_count=1, timeout_s=180.0)
    matches = [e for e in events_seen if e.get("detail-type") == "Email Sent"]
    assert matches, (
        f"positive control failed: no 'Email Sent' event relayed; saw {events_seen!r}"
    )


# ===== helpers =====


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _relay_lambda_zip() -> bytes:
    src = (
        "import json\n"
        "import os\n"
        "import boto3\n\n"
        "_sqs = boto3.client('sqs')\n\n"
        "def handler(event, context):\n"
        "    _sqs.send_message(QueueUrl=os.environ['RELAY_QUEUE_URL'], MessageBody=json.dumps(event))\n"
        "    return {'relayed': True}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", src)
    return buf.getvalue()


def _create_relay_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return url, arn


def _create_relay_role(ctx, queue_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
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
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_exec_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    )
    policy_name = "relay-sqs-send"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sqs:SendMessage",
                        "Resource": queue_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _create_relay_lambda(ctx, role_arn: str, queue_url: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    function_name = ctx.unique_name("sim2real-behav-fn-")
    zip_bytes = _relay_lambda_zip()
    last_err: Exception | None = None
    deadline = time.monotonic() + 60.0
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": zip_bytes},
                Environment={"Variables": {"RELAY_QUEUE_URL": queue_url}},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(
            f"create_function never succeeded (role propagation?): {last_err}"
        )
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, function_name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name).get("State"),
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {function_name} Active",
    )
    return resp["FunctionArn"], function_name


def _allow_eventbridge_invoke(
    ctx, function_name: str, rule_arn: str, statement_id: str = "AllowEventBridgeInvoke"
) -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(
            FunctionName=function_name, StatementId=statement_id
        )
    )


def _create_rule(ctx, event_pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(event_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    return rule_name, rule_arn


def _put_lambda_target(
    ctx, rule_name: str, lambda_arn: str, target_id: str = "relay-target"
) -> None:
    events = ctx.client("events")
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": lambda_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _create_config_set_with_eventbridge(ctx, event_types: list[str]) -> str:
    sesv2 = ctx.client("sesv2")
    sts = ctx.client("sts")
    config_set_name = ctx.unique_name("sim2real-behav-cs-")
    sesv2.create_configuration_set(
        ConfigurationSetName=config_set_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: sesv2.delete_configuration_set(ConfigurationSetName=config_set_name)
    )
    account_id = sts.get_caller_identity()["Account"]
    bus_arn = f"arn:aws:events:{ctx.region}:{account_id}:event-bus/default"
    dest_name = ctx.unique_name("sim2real-behav-dest-")
    sesv2.create_configuration_set_event_destination(
        ConfigurationSetName=config_set_name,
        EventDestinationName=dest_name,
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": event_types,
            "EventBridgeDestination": {"EventBusArn": bus_arn},
        },
    )
    return config_set_name


def _ensure_verified_sender_identity(ctx) -> str:
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


def _send_probe_email(
    ctx, config_set_name: str, from_address: str, to_address: str, subject: str
) -> str:
    sesv2 = ctx.client("sesv2")
    resp = sesv2.send_email(
        FromEmailAddress=from_address,
        Destination={"ToAddresses": [to_address]},
        Content={
            "Simple": {
                "Subject": {"Data": subject},
                "Body": {"Text": {"Data": "sim2real behavioral probe email"}},
            }
        },
        ConfigurationSetName=config_set_name,
    )
    return resp["MessageId"]


def _wait_for_relay_events(
    ctx, queue_url: str, min_count: int = 1, timeout_s: float = 180.0
) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    collected: list[dict[str, Any]] = []

    def probe() -> int:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            try:
                collected.append(json.loads(msg["Body"]))
            except (json.JSONDecodeError, ValueError):
                pass
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        return len(collected)

    _poll_until(
        probe,
        lambda n: n >= min_count,
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"{min_count} relayed event(s) on {queue_url}",
    )
    return collected


def _drain_for(ctx, queue_url: str, timeout_s: float = 75.0) -> list[dict[str, Any]]:
    """Collect whatever arrives on the relay queue over a fixed observation window (used to prove
    absence: unlike _wait_for_relay_events this does not raise on timeout, it just reports what
    it saw)."""
    sqs = ctx.client("sqs")
    collected: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            try:
                collected.append(json.loads(msg["Body"]))
            except (json.JSONDecodeError, ValueError):
                pass
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return collected


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
