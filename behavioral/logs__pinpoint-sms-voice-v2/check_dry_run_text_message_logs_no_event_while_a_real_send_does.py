"""dry-run-text-message-logs-no-event-while-a-real-send-does."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dry-run-text-message-logs-no-event-while-a-real-send-does"
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


def _absent_for(observe, latency_s, *, factor=3.0, floor_s=10.0, poll_s=2.0):
    """Everything ``observe()`` returned over ``max(floor_s, factor * latency_s)`` seconds."""
    deadline = time.monotonic() + max(floor_s, factor * latency_s)
    seen = []
    while True:
        seen.extend(observe())
        if time.monotonic() >= deadline:
            return seen
        time.sleep(poll_s)


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


@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DryRun SendTextMessage is validated and answered with a MessageId but sends nothing, so
    no event is logged for it, while the same send without DryRun logs its final event.

    Reference: https://docs.aws.amazon.com/sms-voice/latest/APIReference/API_SendTextMessage.html
    """
    sms = ctx.client("pinpoint-sms-voice-v2")
    logs = ctx.client("logs")
    config_set, group = _event_sink(ctx, sms, logs, ctx.client("iam"))

    def send(dry_run):
        return sms.send_text_message(
            DestinationPhoneNumber=_SUCCESS_NUMBER, MessageBody="Your test code is 8765",
            MessageType="TRANSACTIONAL", ConfigurationSetName=config_set, DryRun=dry_run,
        ).get("MessageId")

    started = time.monotonic()
    real_id = send(False)
    assert isinstance(real_id, str) and real_id, f"the real send needs a MessageId; got {real_id!r}"
    control = _final_event(ctx, logs, group, real_id)
    latency = time.monotonic() - started
    assert [e.get("eventType") for e in control if e.get("isFinal") is True][-1:] == [
        "TEXT_SUCCESSFUL"], (
        f"the real send's final event is TEXT_SUCCESSFUL; got "
        f"{[(e.get('eventType'), e.get('isFinal')) for e in control]!r}"
    )

    dry_id = send(True)
    assert isinstance(dry_id, str) and dry_id, (
        f"a DryRun send is answered with a MessageId; got {dry_id!r}"
    )
    assert dry_id != real_id, "the DryRun send must get a MessageId of its own"
    leaked = _absent_for(lambda: _events_for(logs, group, dry_id), latency)
    assert leaked == [], (
        f"a DryRun send must log no event; got {[e.get('eventType') for e in leaked]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
