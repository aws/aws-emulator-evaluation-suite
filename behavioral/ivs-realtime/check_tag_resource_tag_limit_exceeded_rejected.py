"""tag-resource-tag-limit-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-tag-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a request that would push a resource's tag count past 50."""
    ivs = ctx.client("ivs-realtime")
    arn = ivs.create_stage(name=ctx.unique_name("sim2real-stage-"))["stage"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=arn))

    too_many_tags = {f"k{i}": f"v{i}" for i in range(51)}
    code, message = _error(lambda: ivs.tag_resource(resourceArn=arn, tags=too_many_tags))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "The resultant tag set must not have more than 50 user tags.", message

    # Effect absent: none of the rejected tags were applied.
    tags_after_rejection = ivs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after_rejection == {}, f"expected no tags applied, got {tags_after_rejection}"

    # Positive control: exactly 50 tags is accepted.
    exactly_50 = {f"k{i}": f"v{i}" for i in range(50)}
    ivs.tag_resource(resourceArn=arn, tags=exactly_50)
    tags_after_success = ivs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after_success == exactly_50, (
        f"expected {len(exactly_50)} tags to persist, got {tags_after_success}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
