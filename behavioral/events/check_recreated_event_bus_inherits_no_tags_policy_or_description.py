"""recreated-event-bus-inherits-no-tags-policy-or-description."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "recreated-event-bus-inherits-no-tags-policy-or-description"
GROUP = "event-bus"
SERVICES = ["events"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A custom bus deleted and recreated under the same name gets the same ARN but none of the old
    tags, resource policy or description; only what the second CreateEventBus supplied is present."""
    events = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")

    first_arn = events.create_event_bus(
        Name=bus, Description="sim2real first incarnation",
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "generation", "Value": "1"}],
    )["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    events.tag_resource(ResourceARN=first_arn, Tags=[{"Key": "generation", "Value": "1-retagged"}])
    events.put_permission(EventBusName=bus, Action="events:PutEvents", Principal="111122223333",
                          StatementId="sim2real-first")

    first = events.describe_event_bus(Name=bus)
    assert first.get("Description") == "sim2real first incarnation", f"first Description {first.get('Description')!r}"
    assert [s["Sid"] for s in json.loads(first["Policy"])["Statement"]] == ["sim2real-first"], (
        "positive control: the first bus must carry the granted statement"
    )
    first_tags = _tags(events, first_arn)
    assert first_tags == {"sim2real": CHECK, "generation": "1-retagged"}, (
        f"TagResource with an existing key must overwrite its value; tags are {first_tags!r}"
    )

    events.delete_event_bus(Name=bus)
    second_arn = events.create_event_bus(Name=bus, Tags=[{"Key": "generation", "Value": "2"}])["EventBusArn"]
    assert second_arn == first_arn, "a recreated bus has the same name-derived ARN"

    second = events.describe_event_bus(Name=bus)
    assert "Policy" not in second, f"the recreated bus must not inherit the old policy, got {second.get('Policy')!r}"
    assert "Description" not in second, (
        f"the recreated bus must not inherit the old Description, got {second.get('Description')!r}"
    )
    second_tags = _tags(events, second_arn)
    assert second_tags == {"generation": "2"}, (
        f"the recreated bus must carry only the tags its own CreateEventBus supplied, got {second_tags!r}"
    )


def _tags(events, arn: str) -> dict:
    return {t["Key"]: t["Value"] for t in events.list_tags_for_resource(ResourceARN=arn)["Tags"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
