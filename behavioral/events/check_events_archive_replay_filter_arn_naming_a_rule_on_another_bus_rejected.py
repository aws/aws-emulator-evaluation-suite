"""events-archive-replay-filter-arn-naming-a-rule-on-another-bus-rejected."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-archive-replay-filter-arn-naming-a-rule-on-another-bus-rejected"

GROUP = "archive-replay"

SERVICES = ["events"]


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """StartReplay with Destination.FilterArns naming a rule on another bus is a ValidationException
    and creates no replay; the same request naming a rule on the destination bus is accepted.
    """
    events = ctx.client("events")
    pattern = json.dumps({"source": [ctx.unique_name("sim2real.arr.src.").replace("-", ".")]})

    source_bus = ctx.unique_name("sim2real-arr-src-")
    source_arn = events.create_event_bus(Name=source_bus, Tags=_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=source_bus))
    other_bus = ctx.unique_name("sim2real-arr-oth-")
    events.create_event_bus(Name=other_bus, Tags=_tags_kv())
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=other_bus))

    own_rule = ctx.unique_name("sim2real-arr-own-")
    own_arn = events.put_rule(Name=own_rule, EventBusName=source_bus, EventPattern=pattern,
                              Tags=_tags_kv())["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=own_rule, EventBusName=source_bus))
    foreign_rule = ctx.unique_name("sim2real-arr-for-")
    foreign_arn = events.put_rule(Name=foreign_rule, EventBusName=other_bus, EventPattern=pattern,
                                  Tags=_tags_kv())["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=foreign_rule, EventBusName=other_bus))

    archive = ctx.unique_name("sim2real-arr-arc-")
    archive_arn = events.create_archive(ArchiveName=archive, EventSourceArn=source_arn)["ArchiveArn"]
    ctx.on_cleanup(lambda: _delete_archive_and_wait(events, archive))
    _wait_archive_enabled(events, archive)

    now = datetime.now(timezone.utc)
    window = {"EventStartTime": now - timedelta(minutes=10), "EventEndTime": now - timedelta(minutes=1)}

    # The destination bus is valid in both requests, isolating the rule-to-bus membership check.
    # StartReplay's model error list does not declare ValidationException.
    refused = ctx.unique_name("sim2real-arr-rp-bad-")
    err = _error(lambda: events.start_replay(
        ReplayName=refused, EventSourceArn=archive_arn,
        Destination={"Arn": source_arn, "FilterArns": [foreign_arn]}, **window
    ))
    expected = (
        "ValidationException",
        "Parameter Destination.FilterArns is not valid. Reason: Rule must be on the destination "
        "event bus.",
    )
    assert err == expected, (
        f"StartReplay into {source_bus!r} filtered to rule {foreign_arn!r} (which lives on "
        f"{other_bus!r}) returned {err!r}, expected {expected!r}"
    )
    absent = _error(lambda: events.describe_replay(ReplayName=refused))
    assert absent == ("ResourceNotFoundException", f"Replay {refused} does not exist."), (
        f"the refused replay {refused!r} is describable afterwards (DescribeReplay -> {absent!r})"
    )
    listed = _list_replay_names(events, refused)
    assert listed == [], f"the refused replay {refused!r} is listed: {listed!r}"

    # Positive control: identical request, but the FilterArns rule is on the destination bus.
    accepted = ctx.unique_name("sim2real-arr-rp-ok-")
    # No DeleteReplay API exists, so the accepted replay is not cleaned up.
    ok = events.start_replay(
        ReplayName=accepted, EventSourceArn=archive_arn,
        Destination={"Arn": source_arn, "FilterArns": [own_arn]}, **window
    )
    assert ok.get("ReplayArn", "").endswith(accepted), f"control StartReplay returned {ok!r}"
    desc = events.describe_replay(ReplayName=accepted)
    assert desc.get("Destination") == {"Arn": source_arn, "FilterArns": [own_arn]}, (
        f"control replay's Destination is {desc.get('Destination')!r}, expected Arn={source_arn!r} "
        f"FilterArns=[{own_arn!r}]"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}]


class _Accepted(Exception):
    """Raised when a call expected to fail succeeds, so it can never read as an error code."""


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code", "<no code>"), error.get("Message")
    raise _Accepted(f"call was expected to be refused but succeeded: {result!r}")


def _list_replay_names(events, prefix: str) -> list[str]:
    names: list[str] = []
    kwargs: dict[str, Any] = {"NamePrefix": prefix}
    while True:
        page = events.list_replays(**kwargs)
        names.extend(r["ReplayName"] for r in page.get("Replays", []))
        if not page.get("NextToken"):
            return names
        kwargs["NextToken"] = page["NextToken"]


def _wait_archive_enabled(events, name: str, *, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = events.describe_archive(ArchiveName=name).get("State")
        if state in ("ENABLED", "CREATE_FAILED", "DISABLED"):
            break
        time.sleep(3)
    assert state == "ENABLED", f"archive {name} settled at State={state!r}, expected 'ENABLED'"


def _delete_archive_and_wait(events, name: str, *, timeout_s: float = 180.0) -> None:
    """The bus cannot be deleted while an archive still references it, so wait for the delete."""
    try:
        events.delete_archive(ArchiveName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise RuntimeError(f"could not delete archive {name}: {exc}") from exc
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            events.describe_archive(ArchiveName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
        time.sleep(3)
    raise RuntimeError(f"archive {name} still present {timeout_s}s after DeleteArchive")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
