"""tag-nonexistent-resource-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-nonexistent-resource-fails"
GROUP = 'tags'
SERVICES = ['events']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource on the ARN of a deleted event bus fails with ResourceNotFoundException; the same
    ARN is first tagged successfully while the bus exists, as a positive control."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    resp = ev.create_event_bus(Name=bus)
    arn = resp["EventBusArn"]
    ctx.on_cleanup(lambda: _delete_bus_if_present(ev, bus))
    ev.tag_resource(ResourceARN=arn, Tags=[{'Key': 'k', 'Value': 'v'}])
    listed = ev.list_tags_for_resource(ResourceARN=arn)
    live_tags = {t["Key"]: t["Value"] for t in listed.get("Tags", [])}
    assert live_tags.get("k") == "v", f"expected positive control tag visible, got {live_tags}"
    ev.delete_event_bus(Name=bus)
    try:
        result = ev.tag_resource(ResourceARN=arn, Tags=[{'Key': 'k2', 'Value': 'v2'}])
    except ClientError as exc:
        err = exc.response.get("Error", {})
    else:
        raise AssertionError(f"TagResource against a deleted bus SUCCEEDED: {result!r}")
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err}"
    expected_message = f"Event bus {bus} does not exist."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )


def _delete_bus_if_present(ev, name):
    """Teardown: the check deletes the bus itself, so a second delete may find nothing."""
    try:
        ev.delete_event_bus(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
