"""schedule-group-name-conflict-message-depends-on-tags."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-group-name-conflict-message-depends-on-tags"
GROUP = "error-semantics"
SERVICES = ["scheduler"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; the resource's own
    not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code: str, message: str) -> None:
    """Assert fn() is refused with exactly this (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        got_code = exc.response["Error"]["Code"]
        got_message = exc.response["Error"]["Message"]
        assert got_code == code, (
            f"expected error code {code!r}, got {got_code!r} (message {got_message!r})"
        )
        assert got_message == message, f"expected message {message!r}, got {got_message!r}"
        return
    raise AssertionError(f"expected a {code!r} refusal, but the call succeeded: {result!r}")


def _tag_pairs(tag_list):
    return frozenset((t["Key"], t["Value"]) for t in tag_list)


def _wait_gone(sch, name: str, *, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    """Poll GetScheduleGroup for ResourceNotFoundException; DeleteScheduleGroup is asynchronous."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sch.get_schedule_group(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"schedule group {name!r} still present {timeout_s}s after delete")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateScheduleGroup for a Name a group already holds is refused by ConflictException whose
    message names the plain Name when the conflicting request carries no Tags and names the
    group's Arn when it does; neither refusal changes the held group's Arn, dates or Tags.
    """
    sch = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-behav-sched-grp-")

    # The legal neighbour for the tagged refusal below: CreateScheduleGroup with Tags succeeds
    # while the Name is free.
    held_tags = [{"Key": "sim2real:origin", "Value": "held"}]
    created = sch.create_schedule_group(Name=name, Tags=held_tags)
    ctx.on_cleanup(_teardown(lambda: sch.delete_schedule_group(Name=name), "ResourceNotFoundException"))
    held_arn = created["ScheduleGroupArn"]

    before = sch.get_schedule_group(Name=name)
    before_tags = _tag_pairs(sch.list_tags_for_resource(ResourceArn=held_arn)["Tags"])
    assert before_tags == _tag_pairs(held_tags), (
        f"the held group's tags were {before_tags!r}, expected {_tag_pairs(held_tags)!r}"
    )

    _UNTAGGED_CONFLICT = ("ConflictException", f"Schedule group {name} already exists.")
    expect_error(lambda: sch.create_schedule_group(Name=name), *_UNTAGGED_CONFLICT)

    _TAGGED_CONFLICT = ("ConflictException", f"Schedule group {held_arn} was modified concurrently.")
    intruding_tags = [{"Key": "sim2real:intruder", "Value": "rejected"}]
    expect_error(
        lambda: sch.create_schedule_group(Name=name, Tags=intruding_tags), *_TAGGED_CONFLICT
    )

    # GetScheduleGroup and ListTagsForResource re-read the held group after both refusals.
    after = sch.get_schedule_group(Name=name)
    assert after["Arn"] == before["Arn"], f"Arn changed from {before['Arn']!r} to {after['Arn']!r}"
    assert after["CreationDate"] == before["CreationDate"], (
        f"CreationDate changed from {before['CreationDate']!r} to {after['CreationDate']!r}"
    )
    assert after["LastModificationDate"] == before["LastModificationDate"], (
        "a rejected conflicting create advanced LastModificationDate: "
        f"{before['LastModificationDate']!r} -> {after['LastModificationDate']!r}"
    )
    after_tags = _tag_pairs(sch.list_tags_for_resource(ResourceArn=held_arn)["Tags"])
    assert after_tags == before_tags, (
        f"a rejected conflicting create changed the held group's tags to {after_tags!r}, "
        f"expected them to stay {before_tags!r}"
    )

    # Once DeleteScheduleGroup completes, the untagged create for the Name succeeds and the new
    # group carries a later CreationDate.
    sch.delete_schedule_group(Name=name)
    _wait_gone(sch, name)
    recreated = sch.create_schedule_group(Name=name)
    assert recreated["ScheduleGroupArn"] == held_arn, (
        f"recreating the freed Name produced Arn {recreated['ScheduleGroupArn']!r}, expected "
        f"the same name-derived Arn {held_arn!r}"
    )
    final = sch.get_schedule_group(Name=name)
    assert final["CreationDate"] > before["CreationDate"], (
        f"recreated group's CreationDate {final['CreationDate']!r} is not later than the "
        f"original held group's {before['CreationDate']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
