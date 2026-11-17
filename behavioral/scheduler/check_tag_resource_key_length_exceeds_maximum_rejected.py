"""tag-resource-key-length-exceeds-maximum-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-key-length-exceeds-maximum-rejected"
GROUP = "tagging"
SERVICES = ["scheduler"]


def _error(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _tag_map(sch, arn):
    resp = sch.list_tags_for_resource(ResourceArn=arn)
    return {t["Key"]: t["Value"] for t in resp["Tags"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a tag key over 128 characters with ValidationException and
    leaves the group's existing tags untouched, while a 128-character key is accepted.
    """
    sch = ctx.client("scheduler")
    # Parameter validation off so the 128-char boundary is the service's own check, not botocore's.
    probe = ctx.client("scheduler", config=Config(parameter_validation=False))

    name = ctx.unique_name("sim2real-behav-sched-grp-")
    created = sch.create_schedule_group(Name=name)
    ctx.on_cleanup(lambda: sch.delete_schedule_group(Name=name))
    arn = created["ScheduleGroupArn"]

    # Positive control: the documented maximum key length is accepted.
    max_key = "k" * 128
    sch.tag_resource(ResourceArn=arn, Tags=[{"Key": max_key, "Value": "fits"}])
    tag_map = _tag_map(sch, arn)
    assert tag_map == {max_key: "fits"}, f"the maximum-length key was not accepted: {tag_map}"

    over_key = "k" * 129
    code, message = _error(
        lambda: probe.tag_resource(ResourceArn=arn, Tags=[{"Key": over_key, "Value": "x"}])
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected_message = (
        f"1 validation error detected: Value '{over_key}' at 'tags.1.member.key' failed to "
        "satisfy constraint: Member must have length less than or equal to 128"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    tag_map = _tag_map(sch, arn)
    assert tag_map == {max_key: "fits"}, (
        f"the rejected over-length key leaked onto the group's tags: {tag_map}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
