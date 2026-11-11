"""system-tag-keys-rejected-on-event-bus-and-tags-unchanged."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "system-tag-keys-rejected-on-event-bus-and-tags-unchanged"
GROUP = "tagging"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource and UntagResource on a custom bus refuse reserved "aws:" tag keys with
    ValidationException, leaving the tags unchanged; a TagResource mixing a legal and a reserved key
    is refused as a whole, so the legal key is not written either."""
    events = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    arn = events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    events.tag_resource(ResourceARN=arn, Tags=[{"Key": "team", "Value": "sim2real"}])
    baseline = _tags(events, arn)
    assert baseline == {"sim2real": CHECK, "team": "sim2real"}, f"positive control: tags are {baseline!r}"

    expected = "Add/Remove system tags is not allowed."

    code, message = _error(lambda: events.tag_resource(
        ResourceARN=arn, Tags=[{"Key": "aws:sim2real", "Value": "x"}]))
    assert (code, message) == ("ValidationException", expected), f"TagResource aws: key gave {code!r} {message!r}"
    assert _tags(events, arn) == baseline, "the refused TagResource changed the bus tags"

    code, message = _error(lambda: events.tag_resource(
        ResourceARN=arn, Tags=[{"Key": "legal", "Value": "y"}, {"Key": "aws:sim2real", "Value": "x"}]))
    assert (code, message) == ("ValidationException", expected), (
        f"TagResource mixing a legal and an aws: key gave {code!r} {message!r}"
    )
    after_mixed = _tags(events, arn)
    assert after_mixed == baseline, (
        f"a refused TagResource is atomic: the legal key must not be written either, tags are {after_mixed!r}"
    )

    code, message = _error(lambda: events.untag_resource(ResourceARN=arn, TagKeys=["aws:sim2real"]))
    assert (code, message) == ("ValidationException", expected), f"UntagResource aws: key gave {code!r} {message!r}"
    assert _tags(events, arn) == baseline, "the refused UntagResource changed the bus tags"


def _tags(events, arn: str) -> dict:
    return {t["Key"]: t["Value"] for t in events.list_tags_for_resource(ResourceARN=arn)["Tags"]}


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
