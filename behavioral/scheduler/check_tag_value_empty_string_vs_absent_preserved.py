"""tag-value-empty-string-vs-absent-preserved."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-value-empty-string-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An explicit empty-string tag value is rejected with ValidationException, not stored as ""."""
    scheduler = ctx.client("scheduler")
    # TagValue has length min 1, so botocore would reject "" client-side; skip that so the
    # service's own validation is what gets exercised.
    probe = ctx.client("scheduler", config=Config(parameter_validation=False))

    group_name = ctx.unique_name("sim2real-sched-grp-")
    group_arn = scheduler.create_schedule_group(Name=group_name)["ScheduleGroupArn"]
    ctx.on_cleanup(lambda: scheduler.delete_schedule_group(Name=group_name))

    # Positive control: tagging works on this resource before the rejection below is trusted.
    scheduler.tag_resource(ResourceArn=group_arn, Tags=[{"Key": "normal-key", "Value": "present"}])
    tags_now = _tag_map(scheduler, group_arn)
    assert tags_now.get("normal-key") == "present", (
        f"expected the positive-control tag to round-trip, got {tags_now.get('normal-key')!r}"
    )

    err = _error_or_raise(
        lambda: probe.tag_resource(ResourceArn=group_arn, Tags=[{"Key": "empty-val", "Value": ""}]),
        what="TagResource with an empty-string tag value",
    )
    code, message = err.get("Code"), err.get("Message")
    assert code == "ValidationException", (
        f"an empty-string tag value must be rejected with ValidationException, got {code!r}"
    )
    expected_message = (
        "1 validation error detected: Value '' at 'tags.1.member.value' failed to satisfy "
        "constraint: Member must have length greater than or equal to 1"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    tags_after_rejection = _tag_map(scheduler, group_arn)
    assert "empty-val" not in tags_after_rejection, (
        f"the rejected empty-string tag was persisted anyway: {tags_after_rejection!r}"
    )
    assert tags_after_rejection.get("normal-key") == "present", (
        "the rejected TagResource call disturbed an existing tag: "
        f"{tags_after_rejection!r}"
    )

    scheduler.untag_resource(ResourceArn=group_arn, TagKeys=["normal-key"])
    tags_final = _tag_map(scheduler, group_arn)
    assert "normal-key" not in tags_final, f"UntagResource left the tag in place: {tags_final!r}"


def _tag_map(scheduler, arn: str) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in scheduler.list_tags_for_resource(ResourceArn=arn)["Tags"]}


def _error_or_raise(fn, *, what: str):
    """Call fn() and return its botocore Error dict (Code, Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected {what} to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
