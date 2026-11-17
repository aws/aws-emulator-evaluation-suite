"""create-archive-anything-but-ignore-case-list-with-a-number-rejected-and-no-archive-created."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-archive-anything-but-ignore-case-list-with-a-number-rejected-and-no-archive-created"
GROUP = "validation"
SERVICES = ["events"]

_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c7")
def run(ctx) -> None:
    """CreateArchive refuses an anything-but equals-ignore-case list holding a number with its exact
    message and creates no archive, while the all-string neighbour list creates one storing it."""
    events = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(Name=bus, Tags=_TAGS)["EventBusArn"]
    ctx.on_cleanup(_teardown(lambda: events.delete_event_bus(Name=bus), "ResourceNotFoundException"))
    source = ctx.unique_name("sim2real.eic.")

    bad_name = ctx.unique_name("sim2real-behav-arch-")
    bad = json.dumps({"detail": {"k": [{"anything-but": {"equals-ignore-case": ["a", 1]}}]},
                      "source": [source]})
    code, msg = _error(lambda: events.create_archive(
        ArchiveName=bad_name, EventSourceArn=bus_arn, EventPattern=bad))
    ctx.on_cleanup(_teardown(lambda: events.delete_archive(ArchiveName=bad_name),
                             "ResourceNotFoundException"))
    column = bad.index('"a", 1') + len('"a", 1') + 1
    at = f' at [Source: (String)"{bad}"; line: 1, column: {column}]'
    want = ("Event pattern is not valid. Reason: Inside anything-but/equals-ignore-case list, "
            f"number|start|null|boolean is not supported.\n{at}\n{at}")
    assert code == "InvalidEventPatternException", f"CreateArchive raised {code!r}: {msg!r}"
    assert msg == want, f"refusal message {msg!r} != {want!r}"

    gone_code, gone_msg = _error(lambda: events.describe_archive(ArchiveName=bad_name))
    assert (gone_code, gone_msg) == ("ResourceNotFoundException", f"Archive {bad_name} does not exist."), (
        f"the refused CreateArchive left an archive behind: {gone_code!r} {gone_msg!r}")

    good_name = ctx.unique_name("sim2real-behav-arch-")
    good = json.dumps({"detail": {"k": [{"anything-but": {"equals-ignore-case": ["a", "1"]}}]},
                       "source": [source]})
    events.create_archive(ArchiveName=good_name, EventSourceArn=bus_arn, EventPattern=good)
    ctx.on_cleanup(_teardown(lambda: events.delete_archive(ArchiveName=good_name),
                             "ResourceNotFoundException"))
    stored = events.describe_archive(ArchiveName=good_name)
    assert stored.get("EventPattern") == good, f"stored pattern {stored.get('EventPattern')!r} != {good!r}"
    assert stored.get("EventSourceArn") == bus_arn, (
        f"archive source {stored.get('EventSourceArn')!r} is not the check's bus")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(call) -> tuple[str, str]:
    """Run `call`; return the (code, message) it raised. Raises if it SUCCEEDED."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<missing Error.Code>"), err.get("Message", "")
    raise AssertionError("the call succeeded where AWS refuses it")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
