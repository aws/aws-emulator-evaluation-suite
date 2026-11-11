"""tag-untag-resource-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-untag-resource-roundtrip"
GROUP = "crud"
SERVICES = ["arc-region-switch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource merges tags into the resource's tag set; UntagResource removes exactly the
    requested keys, leaving the rest untouched."""
    arc = ctx.client("arc-region-switch")
    region_a, region_b = _pick_regions(ctx)
    role_arn = _dummy_role_arn(ctx)

    arn = arc.create_plan(
        name=_plan_name(ctx),
        regions=[region_a, region_b],
        recoveryApproach="activePassive",
        primaryRegion=region_a,
        executionRole=role_arn,
        workflows=[{"workflowTargetAction": "activate"}],
        tags={"keep": "v1"},
    )["plan"]["arn"]
    ctx.on_cleanup(lambda: arc.delete_plan(arn=arn))

    tags_initial = arc.list_tags_for_resource(arn=arn)["resourceTags"]
    assert tags_initial.get("keep") == "v1", (
        f"expected creation-time tag 'keep'='v1' on {arn}, got {tags_initial!r}"
    )

    arc.tag_resource(arn=arn, tags={"env": "sim2real-behav"})
    tags_after_tag = arc.list_tags_for_resource(arn=arn)["resourceTags"]
    assert tags_after_tag.get("env") == "sim2real-behav", (
        f"expected TagResource to add 'env'='sim2real-behav', got {tags_after_tag!r}"
    )
    assert tags_after_tag.get("keep") == "v1", (  # merge, not replace
        f"expected TagResource to merge, leaving 'keep'='v1', got {tags_after_tag!r}"
    )

    arc.untag_resource(arn=arn, resourceTagKeys=["env"])
    tags_after_untag = arc.list_tags_for_resource(arn=arn)["resourceTags"]
    assert "env" not in tags_after_untag, (
        f"expected UntagResource to remove 'env', still present in {tags_after_untag!r}"
    )
    assert tags_after_untag.get("keep") == "v1", (  # untouched by the untag of a different key
        f"expected 'keep'='v1' untouched by untagging 'env', got {tags_after_untag!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _pick_regions(ctx):
    # CreatePlan requires >=2 distinct regions; region_b is a literal because a switching
    # plan's second region is a peer choice, not derivable from ctx.region.
    region_a = ctx.region
    region_b = "us-west-2" if region_a != "us-west-2" else "us-east-1"
    return region_a, region_b


def _plan_name(ctx, prefix="sim2real-arc-"):
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _dummy_role_arn(ctx):
    return f"arn:aws:iam::{_account_id(ctx)}:role/{ctx.unique_name('sim2real-dummy-role-')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
