"""tag-untag-resource-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-untag-resource-roundtrip"
GROUP = "state"
SERVICES = ["gameliftstreams"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags set at CreateStreamGroup time, plus tags added and removed afterwards via
    TagResource/UntagResource, are reflected exactly by ListTagsForResource at each step."""
    gls = ctx.client("gameliftstreams")
    try:
        group = gls.create_stream_group(
            Description=ctx.unique_name("sim2real-behav-gls-sg-"),
            StreamClass="gen6n_small",
            Tags={"phase": "initial"},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(
                f"account has no GPU quota in this Region ({e}); GameLift Streams GPU quotas "
                "default to 0 and must be explicitly requested"
            )
        raise
    arn = group["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: gls.delete_stream_group(Identifier=arn)))

    tags = gls.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags == {"phase": "initial"}, f"expected tags set at creation, got {tags!r}"

    gls.tag_resource(ResourceArn=arn, Tags={"stage": "added"})
    tags = gls.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags == {"phase": "initial", "stage": "added"}, (
        f"expected TagResource to merge with existing tags, got {tags!r}"
    )

    gls.untag_resource(ResourceArn=arn, TagKeys=["phase"])
    tags = gls.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags == {"stage": "added"}, f"expected UntagResource to remove only 'phase', got {tags!r}"


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
