"""tag-untag-list-tags-on-deleted-schedule-group-not-found."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-untag-list-tags-on-deleted-schedule-group-not-found"
GROUP = "tagging"
SERVICES = ["scheduler"]

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestThrottled")


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


def _error(fn):
    """The botocore Error dict (Code, Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_gone(sch, name, *, budget_s=90.0, interval_s=3.0):
    """Poll GetScheduleGroup until it answers ResourceNotFoundException (fully deleted, not
    a transient DELETING), against a clock deadline."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            sch.get_schedule_group(Name=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"schedule group {name!r} did not finish deleting within {budget_s}s")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource, ListTagsForResource and UntagResource each raise ResourceNotFoundException
    naming the group once its schedule group has finished deleting, while an untouched sibling
    group's tags are unaffected.
    """
    sch = ctx.client("scheduler")

    control_name = ctx.unique_name("sim2real-behav-sched-grp-")
    control_resp = _call_retry(
        lambda: sch.create_schedule_group(Name=control_name, Tags=[{"Key": "env", "Value": "dev"}])
    )
    ctx.on_cleanup(lambda: sch.delete_schedule_group(Name=control_name))
    control_arn = control_resp["ScheduleGroupArn"]

    # Positive control: tagging a real group works before the rejections below are trusted.
    control_tags = _call_retry(lambda: sch.list_tags_for_resource(ResourceArn=control_arn))["Tags"]
    assert {t["Key"]: t["Value"] for t in control_tags} == {"env": "dev"}, (
        f"positive control: expected {{env: dev}}, got {control_tags!r}"
    )

    gone_name = ctx.unique_name("sim2real-behav-sched-grp-")
    gone_resp = _call_retry(lambda: sch.create_schedule_group(Name=gone_name))
    gone_arn = gone_resp["ScheduleGroupArn"]
    _call_retry(lambda: sch.delete_schedule_group(Name=gone_name))
    _wait_for_gone(sch, gone_name)

    expected_message = f"Schedule group {gone_name} does not exist."

    err = _error(lambda: sch.tag_resource(ResourceArn=gone_arn, Tags=[{"Key": "k", "Value": "v"}]))
    assert err.get("Code") == "ResourceNotFoundException", (
        f"TagResource on a deleted group: expected ResourceNotFoundException, got {err.get('Code')}"
    )
    assert err.get("Message") == expected_message, (
        f"TagResource on a deleted group: expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    err = _error(lambda: sch.list_tags_for_resource(ResourceArn=gone_arn))
    assert err.get("Code") == "ResourceNotFoundException", (
        f"ListTagsForResource on a deleted group: expected ResourceNotFoundException, got {err.get('Code')}"
    )
    assert err.get("Message") == expected_message, (
        f"ListTagsForResource on a deleted group: expected message {expected_message!r}, "
        f"got {err.get('Message')!r}"
    )

    err = _error(lambda: sch.untag_resource(ResourceArn=gone_arn, TagKeys=["k"]))
    assert err.get("Code") == "ResourceNotFoundException", (
        f"UntagResource on a deleted group: expected ResourceNotFoundException, got {err.get('Code')}"
    )
    assert err.get("Message") == expected_message, (
        f"UntagResource on a deleted group: expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    after_tags = _call_retry(lambda: sch.list_tags_for_resource(ResourceArn=control_arn))["Tags"]
    assert {t["Key"]: t["Value"] for t in after_tags} == {"env": "dev"}, (
        f"the rejected calls against the deleted group disturbed the sibling group's tags: {after_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
