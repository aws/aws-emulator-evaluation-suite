"""tag-resource-exceeds-max-entries-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-max-entries-rejected"
GROUP = "overly-permissive"
SERVICES = ["artifact"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with 51 tags fails BadRequestException and persists none of them, while a 50-tag
    map, the documented maximum, is accepted and fully persisted."""
    art = ctx.client("artifact")
    name = ctx.unique_name("sim2real-artifact-tagmax-")
    inquiry = _create_inquiry(ctx, name, "Which SOC reports cover network security controls?")
    arn = inquiry["arn"]
    ctx.on_cleanup(lambda: _safe_untag(art, arn, [f"k{i}" for i in range(51)]))

    over_limit = {f"k{i}": "v" for i in range(51)}
    code, message = _error(lambda: art.tag_resource(resourceArn=arn, tags=over_limit))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Invalid request body", f"expected AWS's exact refusal message, got {message!r}"

    tags_after_rejected = art.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after_rejected == {}, f"rejected over-limit tag call still persisted tags: {tags_after_rejected}"

    # Positive control: exactly 50 entries (the documented boundary) is accepted.
    at_limit = {f"k{i}": "v" for i in range(50)}
    art.tag_resource(resourceArn=arn, tags=at_limit)
    tags_after_ok = art.list_tags_for_resource(resourceArn=arn)["tags"]
    assert len(tags_after_ok) == 50, f"expected all 50 tags persisted, got {len(tags_after_ok)}"


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


def _error(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected TagResource to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_untag(art, arn, keys):
    try:
        art.untag_resource(resourceArn=arn, tagKeys=keys)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
