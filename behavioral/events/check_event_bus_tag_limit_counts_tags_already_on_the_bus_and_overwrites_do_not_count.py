"""event-bus-tag-limit-counts-tags-already-on-the-bus-and-overwrites-do-not-count."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-bus-tag-limit-counts-tags-already-on-the-bus-and-overwrites-do-not-count"
GROUP = "tagging"
SERVICES = ["events"]

_LIMIT = 50
_TOO_MANY = "The request exceeds the maximum number of tags allowed per resource."


@tags("plane:control", "axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation")
def run(ctx) -> None:
    """The 50-tag bus limit counts tags already on the bus: 40+11 is refused with nothing applied,
    40+10 is accepted, a 51st new key is refused but an overwrite is not, and a 51-tag create fails.
    """
    events = ctx.client("events", config=Config(retries={"total_max_attempts": 1}))
    bus = ctx.unique_name("sim2real-behav-bus-")
    arn = events.create_event_bus(Name=bus, Tags=[{"Key": f"base-{i:02d}", "Value": "v"} for i in range(40)])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    def _tags() -> dict[str, str]:
        return {t["Key"]: t["Value"] for t in events.list_tags_for_resource(ResourceARN=arn)["Tags"]}

    assert len(_tags()) == 40, f"the bus was created with 40 tags but lists {len(_tags())}"

    code, msg = _error(lambda: events.tag_resource(
        ResourceARN=arn, Tags=[{"Key": f"over-{i:02d}", "Value": "v"} for i in range(11)]))
    assert (code, msg) == ("ValidationException", _TOO_MANY), (
        f"adding 11 tags to a bus with 40 gave {code!r}: {msg!r}"
    )
    after = _tags()
    assert len(after) == 40 and not any(k.startswith("over-") for k in after), (
        f"the refused TagResource changed the bus's tags: {len(after)} tags, "
        f"{sum(k.startswith('over-') for k in after)} of the refused keys present"
    )

    events.tag_resource(ResourceARN=arn, Tags=[{"Key": f"fill-{i:02d}", "Value": "v"} for i in range(10)])
    assert len(_tags()) == _LIMIT, f"after adding 10 tags the bus lists {len(_tags())}"

    code, msg = _error(lambda: events.tag_resource(ResourceARN=arn, Tags=[{"Key": "one-more", "Value": "v"}]))
    assert (code, msg) == ("ValidationException", _TOO_MANY), (
        f"a 51st tag on a full bus gave {code!r}: {msg!r}"
    )
    assert "one-more" not in _tags(), "the refused 51st tag is on the bus"

    events.tag_resource(ResourceARN=arn, Tags=[{"Key": "base-00", "Value": "overwritten"}])
    final = _tags()
    assert (len(final), final.get("base-00")) == (_LIMIT, "overwritten"), (
        f"overwriting a key on a full bus must succeed without adding a tag: {len(final)} tags, "
        f"base-00={final.get('base-00')!r}"
    )

    other = ctx.unique_name("sim2real-behav-bus-")
    code, msg = _error(lambda: events.create_event_bus(
        Name=other, Tags=[{"Key": f"k-{i:02d}", "Value": "v"} for i in range(_LIMIT + 1)]))
    if code == "<created>":
        ctx.on_cleanup(lambda: events.delete_event_bus(Name=other))
    assert (code, msg) == ("ValidationException", _TOO_MANY), (
        f"CreateEventBus with 51 tags gave {code!r}: {msg!r}"
    )
    code, msg = _error(lambda: events.describe_event_bus(Name=other))
    assert (code, msg) == ("ResourceNotFoundException", f"Event bus {other} does not exist."), (
        f"the refused CreateEventBus left a bus behind: DescribeEventBus gave {code!r}: {msg!r}"
    )


def _error(fn) -> tuple[str, str]:
    """(code, message) of the refusal; an unexpected success returns a value no code matches."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    return "<created>", "the call succeeded; real AWS refuses it"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
