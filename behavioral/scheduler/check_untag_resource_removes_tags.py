"""untag-resource-removes-tags."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-removes-tags"
GROUP = 'tagging'
SERVICES = ['scheduler']

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestThrottled")


def _track_group(ctx, name):
    sch = ctx.client("scheduler")
    ctx.on_cleanup(lambda: sch.delete_schedule_group(Name=name))


def _call_retry(fn, *, attempts=10, base_delay=1.5):
    last_exc = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _THROTTLE_CODES:
                raise
            last_exc = exc
            time.sleep(base_delay * (i + 1))
    raise last_exc


def _tag(ctx, arn, tags):
    sch = ctx.client("scheduler")
    _call_retry(lambda: sch.tag_resource(ResourceArn=arn, Tags=tags))


def _untag(ctx, arn, keys):
    sch = ctx.client("scheduler")
    _call_retry(lambda: sch.untag_resource(ResourceArn=arn, TagKeys=keys))


def _tag_map(ctx, arn):
    sch = ctx.client("scheduler")
    resp = _call_retry(lambda: sch.list_tags_for_resource(ResourceArn=arn))
    return {t["Key"]: t["Value"] for t in resp.get("Tags", [])}

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the specified keys, leaving other tags intact.

    Scheduler tagging is scoped to schedule-group ARNs.
    """
    sch = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-behav-" + "sched-grp-")
    resp = sch.create_schedule_group(Name=name)
    _track_group(ctx, name)
    arn = resp["ScheduleGroupArn"]

    _tag(ctx, 
        arn,
        [{"Key": "keep", "Value": "yes"}, {"Key": "drop", "Value": "no"}],
    )
    tag_map = _tag_map(ctx, arn)
    assert tag_map.get("keep") == "yes" and tag_map.get("drop") == "no", (
        f"tags not applied: {tag_map}"
    )

    _untag(ctx, arn, ["drop"])

    tag_map = _tag_map(ctx, arn)
    assert tag_map.get("keep") == "yes", f"unrelated tag was removed: {tag_map}"
    assert "drop" not in tag_map, f"'drop' tag survived untag: {tag_map}"

    # Untagging a key that is not present must be a no-op, not an error.
    _untag(ctx, arn, ["never-existed"])
    tag_map = _tag_map(ctx, arn)
    assert tag_map.get("keep") == "yes", (
        f"untag of a nonexistent key must be a no-op: {tag_map}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
