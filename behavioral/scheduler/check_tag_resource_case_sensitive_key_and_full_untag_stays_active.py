"""tag-resource-case-sensitive-key-and-full-untag-stays-active."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-case-sensitive-key-and-full-untag-stays-active"
GROUP = "tagging"
SERVICES = ["scheduler"]

_THROTTLE = frozenset({"ThrottlingException", "TooManyRequestsException", "RequestThrottled"})


def _retry(call, *, tries=8, start_delay=1.0):
    """Run ``call()``, backing off with doubling delay only on scheduler's own throttle codes."""
    delay = start_delay
    for attempt in range(tries):
        try:
            return call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _THROTTLE or attempt == tries - 1:
                raise
            time.sleep(delay)
            delay *= 2


def _tag_map(sch, arn):
    tag_list = _retry(lambda: sch.list_tags_for_resource(ResourceArn=arn))["Tags"]
    return {t["Key"]: t["Value"] for t in tag_list}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource overwrites a tag sharing its exact key, keeps a key differing only in
    case as a separate entry, and UntagResource of every key leaves the group tagless while
    GetScheduleGroup still reports it ACTIVE.
    """
    sch = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-behav-sched-grp-")
    created = _retry(lambda: sch.create_schedule_group(Name=name))
    ctx.on_cleanup(lambda: sch.delete_schedule_group(Name=name))
    arn = created["ScheduleGroupArn"]

    _retry(lambda: sch.tag_resource(ResourceArn=arn, Tags=[{"Key": "Stage", "Value": "alpha"}]))
    tag_map = _tag_map(sch, arn)
    assert tag_map == {"Stage": "alpha"}, f"first tag not reflected: {tag_map}"

    # Re-tagging the identical key "Stage" replaces its value rather than adding an entry.
    _retry(lambda: sch.tag_resource(ResourceArn=arn, Tags=[{"Key": "Stage", "Value": "beta"}]))
    tag_map = _tag_map(sch, arn)
    assert tag_map == {"Stage": "beta"}, f"re-tagging the exact key did not overwrite it: {tag_map}"

    # A key differing only in case ("stage") is a distinct entry, not a case-insensitive match.
    _retry(lambda: sch.tag_resource(ResourceArn=arn, Tags=[{"Key": "stage", "Value": "gamma"}]))
    tag_map = _tag_map(sch, arn)
    assert tag_map == {"Stage": "beta", "stage": "gamma"}, (
        f"the case-differing key merged with 'Stage' instead of staying distinct: {tag_map}"
    )

    state_before = _retry(lambda: sch.get_schedule_group(Name=name))["State"]
    assert state_before == "ACTIVE", f"group was not ACTIVE before untagging: {state_before}"

    _retry(lambda: sch.untag_resource(ResourceArn=arn, TagKeys=["Stage", "stage"]))
    tag_map = _tag_map(sch, arn)
    assert tag_map == {}, f"untagging every key left tags behind: {tag_map}"

    state_after = _retry(lambda: sch.get_schedule_group(Name=name))["State"]
    assert state_after == "ACTIVE", (
        f"losing all its tags changed the group's state away from ACTIVE: {state_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
