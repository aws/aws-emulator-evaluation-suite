"""text-to-success-simulator-number-logs-a-final-successful-event."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "text-to-success-simulator-number-logs-a-final-successful-event"
GROUP = "sms-simulator-events"
SERVICES = ["logs", "pinpoint-sms-voice-v2"]

# real-data: the AWS-published Sweden success simulator destination; it stays inside the service.
_SUCCESS_NUMBER = "+46790645100"
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
    """A text to the success simulator number is accepted and its final logged event is
    TEXT_SUCCESSFUL from the default NOTICE sender, carrying the message id and send context.

    Reference: https://docs.aws.amazon.com/sms-voice/latest/userguide/test-phone-numbers.html
    """
    sms = ctx.client("pinpoint-sms-voice-v2")
    logs = ctx.client("logs")
    config_set, group = _event_sink(ctx, sms, logs, ctx.client("iam"))

    marker = ctx.unique_name("order-")
    sent = sms.send_text_message(
        DestinationPhoneNumber=_SUCCESS_NUMBER, MessageBody="Your test code is 4321",
        MessageType="TRANSACTIONAL", ConfigurationSetName=config_set,
        Context={"order": marker},
    )
    message_id = sent.get("MessageId")
    assert isinstance(message_id, str) and message_id, (
        f"SendTextMessage must return a MessageId; got {sorted(sent)!r}"
    )

    events = _final_event(ctx, logs, group, message_id)
    finals = [e for e in events if e.get("isFinal") is True]
    final = finals[-1]
    assert final.get("eventType") == "TEXT_SUCCESSFUL", (
        f"the final event for a success simulator number is TEXT_SUCCESSFUL; got "
        f"{final.get('eventType')!r}"
    )
    assert final.get("messageStatus") == "SUCCESSFUL", (
        f"messageStatus mismatch: {final.get('messageStatus')!r}"
    )
    assert final.get("messageStatusDescription") == "Message has been accepted by phone carrier", (
        f"messageStatusDescription mismatch: {final.get('messageStatusDescription')!r}"
    )
    assert final.get("destinationPhoneNumber") == _SUCCESS_NUMBER, (
        f"the event must name the destination it was sent to; got "
        f"{final.get('destinationPhoneNumber')!r}"
    )
    assert final.get("isoCountryCode") == "SE", (
        f"isoCountryCode mismatch: {final.get('isoCountryCode')!r}"
    )
    assert final.get("originationPhoneNumber") == "NOTICE", (
        f"with no origination identity in the account the sender is NOTICE; got "
        f"{final.get('originationPhoneNumber')!r}"
    )
    assert final.get("messageType") == "TRANSACTIONAL", (
        f"messageType mismatch: {final.get('messageType')!r}"
    )
    assert final.get("context") == {"order": marker}, (
        f"the send's Context must come back on the event; got {final.get('context')!r}"
    )
    assert final.get("totalMessageParts") == 1, (
        f"a short GSM body is one part; got {final.get('totalMessageParts')!r}"
    )
    failed = [e.get("eventType") for e in events
              if e.get("messageStatus") not in ("SUCCESSFUL", "DELIVERED", "PENDING", "QUEUED")]
    assert failed == [], f"a success simulator number logs no failure event; got {failed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
