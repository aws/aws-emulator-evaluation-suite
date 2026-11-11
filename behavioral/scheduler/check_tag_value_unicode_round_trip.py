"""tag-value-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-unicode-round-trip"
GROUP = "representation"
SERVICES = ["scheduler"]

_UNICODE_TAGS = {
    "\u00e9quipe-\u65e5\u672c": "r\u00e9sum\u00e9_\u4e2d\u6587",
    "team\u00df": "caf\u00e9-\u0645\u0631\u062d\u0628\u0627",
}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode tag keys/values on a ScheduleGroup survive TagResource->ListTagsForResource, and a
    reserved "aws:" key prefix is rejected with ValidationException and never listed."""
    scheduler = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-behav-group-")

    group = scheduler.create_schedule_group(Name=name)
    group_arn = group["ScheduleGroupArn"]
    ctx.on_cleanup(lambda: scheduler.delete_schedule_group(Name=name))

    scheduler.tag_resource(
        ResourceArn=group_arn,
        Tags=[{"Key": k, "Value": v} for k, v in _UNICODE_TAGS.items()],
    )

    got = scheduler.list_tags_for_resource(ResourceArn=group_arn)
    got_tags = {t["Key"]: t["Value"] for t in got["Tags"]}

    for key, value in _UNICODE_TAGS.items():
        assert key in got_tags, f"unicode tag key {key!r} missing from ListTagsForResource: {got_tags!r}"
        assert got_tags[key] == value, f"tag value mutated for {key!r}: {got_tags[key]!r} != {value!r}"

    # --- negative: reserved "aws:" tag-key prefix is rejected, existing unicode tags untouched ---
    err = _error(
        lambda: scheduler.tag_resource(
            ResourceArn=group_arn,
            Tags=[{"Key": "aws:reserved-prefix", "Value": "should-not-apply"}],
        )
    )
    code, message = err.get("Code"), err.get("Message")
    assert code == "ValidationException", f"expected ValidationException for reserved tag-key prefix, got {code!r}"
    expected_message = "Caller is an end user and not allowed to modify system tags."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    got_after = scheduler.list_tags_for_resource(ResourceArn=group_arn)
    after_tags = {t["Key"]: t["Value"] for t in got_after["Tags"]}
    assert "aws:reserved-prefix" not in after_tags, "reserved-prefix tag key was applied despite rejection"
    for key, value in _UNICODE_TAGS.items():
        assert after_tags.get(key) == value, "existing unicode tags were disturbed by the rejected TagResource call"


def _error(fn):
    """Call fn() and return its botocore Error dict (Code, Message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

