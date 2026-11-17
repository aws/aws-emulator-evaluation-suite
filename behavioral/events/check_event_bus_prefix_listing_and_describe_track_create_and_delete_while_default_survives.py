"""event-bus-prefix-listing-and-describe-track-create-and-delete-while-default-survives."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-bus-prefix-listing-and-describe-track-create-and-delete-while-default-survives"
GROUP = 'event-bus'
SERVICES = ['events']


def expect_error(fn, code, message):
    """Assert fn() raises exactly (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; the resource's own not_found
    codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _list_names(ev, **kwargs) -> list:
    """Every bus Name from a fully paginated ListEventBuses(**kwargs)."""
    names = []
    while True:
        resp = ev.list_event_buses(**kwargs)
        names.extend(b["Name"] for b in resp.get("EventBuses", []))
        token = resp.get("NextToken")
        if not token:
            return names
        kwargs = dict(kwargs, NextToken=token)


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEventBuses(NamePrefix=name) lists a created bus with its Name and Arn, and returns
    EventBuses [] for that prefix once DeleteEventBus removes it; DescribeEventBus then fails
    ResourceNotFoundException with its exact message, while the default bus stays listed."""
    ev = ctx.client("events")
    name = ctx.unique_name("sim2real-behav-bus-")
    created = ev.create_event_bus(Name=name)
    ctx.on_cleanup(_teardown(lambda n=name: ev.delete_event_bus(Name=n), "ResourceNotFoundException"))

    before = ev.list_event_buses(NamePrefix=name).get("EventBuses", [])
    assert len(before) == 1, f"expected exactly one bus for prefix {name!r}, got {before!r}"
    assert before[0]["Name"] == name, f"expected Name {name!r}, got {before[0]['Name']!r}"
    assert before[0]["Arn"] == created["EventBusArn"], (
        f"expected Arn {created['EventBusArn']!r}, got {before[0]['Arn']!r}"
    )

    ev.delete_event_bus(Name=name)

    after = ev.list_event_buses(NamePrefix=name).get("EventBuses", [])
    assert after == [], f"expected EventBuses [] for prefix {name!r} after delete, got {after!r}"

    _NOT_FOUND = ("ResourceNotFoundException", f"Event bus {name} does not exist.")
    expect_error(lambda: ev.describe_event_bus(Name=name), *_NOT_FOUND)

    all_names = _list_names(ev)
    assert "default" in all_names, (
        f"default bus must still be listed by an unfiltered ListEventBuses, got {all_names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
