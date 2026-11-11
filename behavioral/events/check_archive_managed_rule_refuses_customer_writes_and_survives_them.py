"""archive-managed-rule-refuses-customer-writes-and-survives-them."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "archive-managed-rule-refuses-customer-writes-and-survives-them"
GROUP = "archive"
SERVICES = ["events"]

_RULE_APPEAR_TIMEOUT_S = 60.0
_ARCHIVE_DELETE_TIMEOUT_S = 180.0


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """The rule CreateArchive makes on its bus is service-managed: every customer write to it fails
    with ManagedRuleException and its exact message, and leaves the rule's state, pattern and
    single target unchanged; the same writes on a customer rule on that bus succeed."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(
        Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    queue_name = ctx.unique_name("sim2real-behav-q-")
    queue_url = sqs.create_queue(QueueName=queue_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    # Positive control: a customer rule on the same bus.
    own_rule = ctx.unique_name("sim2real-behav-rule-")
    source = ctx.unique_name("sim2real.archive.")
    own_rule_arn = events.put_rule(
        Name=own_rule, EventBusName=bus, EventPattern=json.dumps({"source": [source]}),
        State="ENABLED",
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=own_rule, EventBusName=bus))

    archive = ctx.unique_name("sim2real-arc-")
    archive_pattern = {"source": [source]}
    events.create_archive(
        ArchiveName=archive, EventSourceArn=bus_arn, EventPattern=json.dumps(archive_pattern)
    )
    ctx.on_cleanup(lambda: _delete_archive_and_wait(events, archive))

    managed = f"Events-Archive-{archive}"
    managed_arn = f"arn:aws:events:{ctx.region}:{ctx.account}:rule/{bus}/{managed}"
    listed = _poll_for_rule(events, bus, managed)
    assert listed["Arn"] == managed_arn, (
        f"the archive's managed rule has ARN {listed['Arn']!r}, expected {managed_arn!r}"
    )
    assert listed.get("ManagedBy"), (
        f"the rule CreateArchive made must report who manages it (ManagedBy), got {listed!r}"
    )
    expected_pattern = {**archive_pattern, "replay-name": [{"exists": False}]}
    assert json.loads(listed["EventPattern"]) == expected_pattern, (
        f"the managed rule must match what the archive matches and exclude replayed events: "
        f"expected {expected_pattern!r}, got {listed['EventPattern']!r}"
    )
    targets_before = events.list_targets_by_rule(Rule=managed, EventBusName=bus)["Targets"]
    assert [t["Id"] for t in targets_before] == [managed], (
        f"the managed rule must carry exactly one target, Id {managed!r}; got {targets_before!r}"
    )

    # Only DeleteRule and RemoveTargets point at the Force parameter in their refusal.
    plain = f"{managed} is a managed rule."
    forceable = f"{managed} is a managed rule. Set 'force' parameter to true to override."
    refusals = {
        "DisableRule": (lambda: events.disable_rule(Name=managed, EventBusName=bus), plain),
        "EnableRule": (lambda: events.enable_rule(Name=managed, EventBusName=bus), plain),
        "PutRule": (
            lambda: events.put_rule(
                Name=managed, EventBusName=bus,
                EventPattern=json.dumps({"source": ["sim2real.hijack"]}),
            ),
            plain,
        ),
        "DeleteRule": (lambda: events.delete_rule(Name=managed, EventBusName=bus), forceable),
        "RemoveTargets": (
            lambda: events.remove_targets(Rule=managed, EventBusName=bus, Ids=[managed]),
            forceable,
        ),
        "TagResource": (
            lambda: events.tag_resource(
                ResourceARN=managed_arn, Tags=[{"Key": "sim2real", "Value": CHECK}]
            ),
            f"Tag related operations on the managed rule {managed} is not allowed.",
        ),
        "PutTargets": (
            lambda: events.put_targets(
                Rule=managed, EventBusName=bus, Targets=[{"Id": "sim2real-q", "Arn": queue_arn}]
            ),
            plain,
        ),
    }
    for op, (call, expected_message) in refusals.items():
        code, message = _error(call)
        assert code == "ManagedRuleException", (
            f"{op} on the archive's managed rule {managed!r} must be refused with "
            f"ManagedRuleException, got {code!r}: {message!r}"
        )
        assert message == expected_message, (
            f"{op} on the managed rule was refused with message {message!r}, expected "
            f"{expected_message!r}"
        )

    after = events.describe_rule(Name=managed, EventBusName=bus)
    assert after["State"] == "ENABLED", (
        f"refused DisableRule/PutRule calls changed the managed rule's state to {after['State']!r}"
    )
    assert json.loads(after["EventPattern"]) == expected_pattern, (
        f"a refused PutRule changed the managed rule's pattern to {after['EventPattern']!r}"
    )
    targets_after = events.list_targets_by_rule(Rule=managed, EventBusName=bus)["Targets"]
    assert targets_after == targets_before, (
        f"refused PutTargets/RemoveTargets changed the managed rule's targets from "
        f"{targets_before!r} to {targets_after!r}"
    )

    # The same writes on the customer's own rule go through.
    events.disable_rule(Name=own_rule, EventBusName=bus)
    own_state = events.describe_rule(Name=own_rule, EventBusName=bus)["State"]
    assert own_state == "DISABLED", (
        f"positive control: DisableRule on the customer's rule left it {own_state!r}"
    )
    events.tag_resource(ResourceARN=own_rule_arn, Tags=[{"Key": "sim2real", "Value": CHECK}])
    own_tags = events.list_tags_for_resource(ResourceARN=own_rule_arn)["Tags"]
    assert own_tags == [{"Key": "sim2real", "Value": CHECK}], (
        f"positive control: TagResource on the customer's rule left tags {own_tags!r}"
    )


def _poll_for_rule(events, bus: str, name: str) -> dict:
    deadline = time.monotonic() + _RULE_APPEAR_TIMEOUT_S
    while time.monotonic() < deadline:
        for page in events.get_paginator("list_rules").paginate(
            EventBusName=bus, NamePrefix="Events-Archive-"
        ):
            for rule in page["Rules"]:
                if rule["Name"] == name:
                    return rule
        time.sleep(2)
    raise AssertionError(
        f"CreateArchive never produced its managed rule {name!r} on bus {bus!r} within "
        f"{_RULE_APPEAR_TIMEOUT_S}s"
    )


def _delete_archive_and_wait(events, name: str) -> None:
    """DeleteArchive is asynchronous and the bus cannot be deleted while it still exists."""
    events.delete_archive(ArchiveName=name)
    deadline = time.monotonic() + _ARCHIVE_DELETE_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            events.describe_archive(ArchiveName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"archive {name} still exists {_ARCHIVE_DELETE_TIMEOUT_S}s after DeleteArchive")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
