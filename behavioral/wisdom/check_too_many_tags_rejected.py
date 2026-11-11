"""too-many-tags-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "too-many-tags-rejected"
GROUP = "overly-permissive"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adding 15 tags to a resource holding 40 fails with BadRequestException and the exact
    50-tag message and persists none; after untagging down to 25, the same call succeeds.
    """
    wisdom = ctx.client("wisdom")
    assistant = wisdom.create_assistant(name=ctx.unique_name("sim2real-asst-"), type="AGENT")["assistant"]
    assistant_id = assistant["assistantId"]
    assistant_arn = assistant["assistantArn"]
    ctx.on_cleanup(lambda: wisdom.delete_assistant(assistantId=assistant_id))

    # positive control: tagging comfortably within the limit succeeds
    first_batch = {f"k{i}": f"v{i}" for i in range(40)}
    wisdom.tag_resource(resourceArn=assistant_arn, tags=first_batch)
    tags_after_first = wisdom.list_tags_for_resource(resourceArn=assistant_arn)["tags"]
    assert tags_after_first == first_batch, f"expected {first_batch}, got {tags_after_first}"

    # pushing the cumulative total (40 existing + 15 new = 55) past 50 is rejected
    second_batch = {f"j{i}": f"w{i}" for i in range(15)}
    code, message = _error(lambda: wisdom.tag_resource(resourceArn=assistant_arn, tags=second_batch))
    assert code == "BadRequestException", f"expected a too-many-tags rejection, got {code!r}"
    assert message == "The resultant tag set must not have more than 50 user tags.", f"message={message!r}"

    # none of the offending second-batch tags were persisted; the original 40 remain intact
    tags_after_reject = wisdom.list_tags_for_resource(resourceArn=assistant_arn)["tags"]
    assert tags_after_reject == first_batch, f"expected {first_batch}, got {tags_after_reject}"

    # restore: untag enough of the first batch that the cumulative total drops back under
    # 50 (40 -> 25), then the identical second_batch call that was just rejected succeeds,
    # proving the rejection tracked the resource's real cumulative count and not a fixed
    # always-reject stub
    keys_to_remove = [f"k{i}" for i in range(25, 40)]
    wisdom.untag_resource(resourceArn=assistant_arn, tagKeys=keys_to_remove)
    remaining_first_batch = {k: v for k, v in first_batch.items() if k not in keys_to_remove}
    wisdom.tag_resource(resourceArn=assistant_arn, tags=second_batch)
    expected_after_restore = {**remaining_first_batch, **second_batch}
    tags_after_restore = wisdom.list_tags_for_resource(resourceArn=assistant_arn)["tags"]
    assert tags_after_restore == expected_after_restore, (
        f"expected the identical second_batch call to succeed once total tags dropped to "
        f"{len(remaining_first_batch)}, got {tags_after_restore}"
    )


def _error(fn):
    """Call fn(); return the rejected call's (error code, error message). An unexpected
    success raises, so a target accepting what AWS refuses is reported as such."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
