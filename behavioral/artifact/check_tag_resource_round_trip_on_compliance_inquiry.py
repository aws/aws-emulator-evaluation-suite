"""tag-resource-round-trip-on-compliance-inquiry."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-round-trip-on-compliance-inquiry"
GROUP = "tagging"
SERVICES = ["artifact"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a compliance-inquiry
    ARN: the tag is visible after TagResource and gone after UntagResource."""
    art = ctx.client("artifact")
    name = ctx.unique_name("sim2real-artifact-tagrt-")
    inquiry = _create_inquiry(ctx, name, "What data residency options does AWS offer?")
    arn = inquiry["arn"]

    art.tag_resource(resourceArn=arn, tags={"sim2real-env": "test"})
    ctx.on_cleanup(lambda: _safe_untag(art, arn, ["sim2real-env"]))

    tags = art.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("sim2real-env") == "test", f"expected tag to be visible, got {tags}"

    art.untag_resource(resourceArn=arn, tagKeys=["sim2real-env"])
    tags_after = art.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "sim2real-env" not in tags_after, f"tag still present after UntagResource: {tags_after}"


def _create_inquiry(ctx, name, query_text, support_mode="AI_ONLY"):
    art = ctx.client("artifact")
    try:
        return art.create_compliance_inquiry(
            name=name,
            inquiryContent={"query": query_text},
            supportMode=support_mode,
        )["complianceInquirySummary"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            raise AssertionError(
                "account is not opted into AWS Artifact Assurance Assistant "
                "(CreateComplianceInquiry requires feature opt-in); cannot create an "
                "inquiry resource to tag"
            ) from e
        raise


def _safe_untag(art, arn, keys):
    try:
        art.untag_resource(resourceArn=arn, tagKeys=keys)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
