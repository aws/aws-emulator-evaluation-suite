"""text-to-failure-simulator-number-is-accepted-then-logs-an-undelivered-final-event."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "text-to-failure-simulator-number-is-accepted-then-logs-an-undelivered-final-event"
GROUP = "sms-simulator-events"
SERVICES = ["logs", "pinpoint-sms-voice-v2"]

# real-data: the AWS-published Sweden failure simulator destination; it stays inside the service.
_FAILURE_NUMBER = "+46790645102"
_LABEL = {"sim2real": CHECK}


def _teardown(undo, *gone):
    """A cleanup that runs ``undo()`` and raises on failure unless the error says it is gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in gone:
                return
            raise

    return run_undo


def _event_sink(ctx, sms, logs, iam):
    """A configuration set whose event destination writes every event to a fresh log group."""
    name = ctx.unique_name("sim2real-smsev-")
    group = f"/sim2real/sms-events/{name}"
    logs.create_log_group(logGroupName=group, tags=_LABEL)
    ctx.on_cleanup(_teardown(lambda: logs.delete_log_group(logGroupName=group),
                             "ResourceNotFoundException"))
    group_arn = f"arn:aws:logs:{ctx.region}:{ctx.account}:log-group:{group}"

    config_arn = sms.create_configuration_set(
        ConfigurationSetName=name, Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ConfigurationSetArn"]
    ctx.on_cleanup(_teardown(lambda: sms.delete_configuration_set(ConfigurationSetName=name),
                             "ResourceNotFoundException"))

    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "sms-voice.amazonaws.com"},
        "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account},
                      "ArnLike": {"aws:SourceArn": config_arn}}}]}
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                               Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    writer = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"],
        "Resource": [f"{group_arn}:*"]}]}
    iam.put_role_policy(RoleName=name, PolicyName="write-events",
                        PolicyDocument=json.dumps(writer))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name,
                                                            PolicyName="write-events"),
                             "NoSuchEntity"))
    # fixed-wait: IAM exposes no condition that says a new role is assumable by the service
    time.sleep(10)
    sms.create_event_destination(
        ConfigurationSetName=name, EventDestinationName="all-to-logs",
        MatchingEventTypes=["ALL"],
        CloudWatchLogsDestination={"IamRoleArn": role_arn, "LogGroupArn": group_arn},
    )
    return name, group


def _events_for(logs, group, message_id):
    """Every event record in ``group`` that names ``message_id``."""
    found = []
    pages = logs.get_paginator("filter_log_events").paginate(
        logGroupName=group, filterPattern=f'{{ $.messageId = "{message_id}" }}')
    for page in pages:
        found.extend(json.loads(e["message"]) for e in page["events"])
    return found


def _final_event(ctx, logs, group, message_id, cap_s=180.0):
    """Poll until the event record marked final for ``message_id`` is logged; return all of them."""
    left = ctx.time_left()
    budget = cap_s if left is None else max(5.0, min(cap_s, left - 10.0))
    deadline = time.monotonic() + budget
    seen = []
    while time.monotonic() < deadline:
        seen = _events_for(logs, group, message_id)
        if any(e.get("isFinal") is True for e in seen):
            return seen
        time.sleep(3)
    raise AssertionError(
        f"no final event for the message within {budget:.0f}s; event types logged: "
        f"{[e.get('eventType') for e in seen]!r}"
    )


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A text to the failure simulator number is still accepted synchronously; the refusal arrives
    only as its final logged event, TEXT_BLOCKED, and no successful event is ever logged for it.

    Reference: https://docs.aws.amazon.com/sms-voice/latest/userguide/test-phone-numbers.html
    """
    sms = ctx.client("pinpoint-sms-voice-v2")
    logs = ctx.client("logs")
    config_set, group = _event_sink(ctx, sms, logs, ctx.client("iam"))

    marker = ctx.unique_name("ticket-")
    sent = sms.send_text_message(
        DestinationPhoneNumber=_FAILURE_NUMBER, MessageBody="Your ticket is ready",
        MessageType="TRANSACTIONAL", ConfigurationSetName=config_set,
        Context={"ticket": marker},
    )
    message_id = sent.get("MessageId")
    assert isinstance(message_id, str) and message_id, (
        f"SendTextMessage accepts the send and returns a MessageId; got {sorted(sent)!r}"
    )

    events = _final_event(ctx, logs, group, message_id)
    final = [e for e in events if e.get("isFinal") is True][-1]
    assert final.get("eventType") == "TEXT_BLOCKED", (
        f"the final event for the failure simulator number is TEXT_BLOCKED; got "
        f"{final.get('eventType')!r}"
    )
    assert final.get("messageStatus") == "BLOCKED", (
        f"messageStatus mismatch: {final.get('messageStatus')!r}"
    )
    assert final.get("messageStatusDescription") == "Phone has blocked SMS", (
        f"messageStatusDescription mismatch: {final.get('messageStatusDescription')!r}"
    )
    assert final.get("destinationPhoneNumber") == _FAILURE_NUMBER, (
        f"the event must name the destination it was sent to; got "
        f"{final.get('destinationPhoneNumber')!r}"
    )
    assert final.get("context") == {"ticket": marker}, (
        f"the send's Context must come back on the failure event too; got {final.get('context')!r}"
    )
    succeeded = [e.get("eventType") for e in events
                 if e.get("messageStatus") in ("SUCCESSFUL", "DELIVERED")]
    assert succeeded == [], (
        f"a blocked message logs no successful event; got {succeeded!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
