"""braket-tag-and-untag-resource-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "braket-tag-and-untag-resource-lifecycle"
GROUP = "state"
SERVICES = ["braket"]

# Spending limits are a QPU-only cost control (CreateSpendingLimit rejects simulator devices with
# ValidationException). QPU device residency is fixed by AWS per Region and does not follow
# ctx.region, so the client is pinned to a Region with a resident QPU. Pinned through
# ctx.client(..., region=).
QPU_REGION = "us-east-1"
QPU_DEVICE_ARN = "arn:aws:braket:us-east-1::device/qpu/ionq/Forte-1"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource mutate the tag set observed via ListTagsForResource; untagging
    a key that was never set is a harmless no-op that leaves other tags intact. Once the
    resource is deleted, the same tag operations fail not-found.
    """
    braket = ctx.client("braket", region=QPU_REGION)

    arn = braket.create_spending_limit(
        clientToken=ctx.unique_name("sim2real-tags-create-"),
        deviceArn=QPU_DEVICE_ARN,
        spendingLimit="3.00",
        tags={"sim2real-other": "keep"},
    )["spendingLimitArn"]
    deleted = False
    try:
        current = braket.list_tags_for_resource(resourceArn=arn)["tags"]
        assert current.get("sim2real-other") == "keep", (
            f"tags at creation missing sim2real-other=keep: {current}"
        )

        braket.tag_resource(resourceArn=arn, tags={"sim2real-team": "quantum"})
        current = braket.list_tags_for_resource(resourceArn=arn)["tags"]
        assert current.get("sim2real-team") == "quantum", (
            f"tag_resource did not set sim2real-team=quantum: {current}"
        )
        assert current.get("sim2real-other") == "keep", (
            f"tag_resource disturbed the pre-existing sim2real-other tag: {current}"
        )

        braket.untag_resource(resourceArn=arn, tagKeys=["sim2real-team"])
        current = braket.list_tags_for_resource(resourceArn=arn)["tags"]
        assert "sim2real-team" not in current, (
            f"untag_resource left sim2real-team present: {current}"
        )
        assert current.get("sim2real-other") == "keep", (
            f"untag_resource disturbed the pre-existing sim2real-other tag: {current}"
        )

        # Untagging a key that was never present must not raise and must not disturb other tags.
        braket.untag_resource(resourceArn=arn, tagKeys=["sim2real-never-set"])
        current = braket.list_tags_for_resource(resourceArn=arn)["tags"]
        assert current.get("sim2real-other") == "keep", (
            f"untagging an absent key disturbed the pre-existing sim2real-other tag: {current}"
        )
        assert "sim2real-never-set" not in current, (
            f"untagging an absent key materialized it: {current}"
        )

        braket.delete_spending_limit(spendingLimitArn=arn)
        deleted = True
        # Real AWS answers a deleted spending limit's tag operations with NotFoundException,
        # not the ResourceNotFoundException a modeled-shape guess would suggest.
        err = _client_error(lambda: braket.list_tags_for_resource(resourceArn=arn))
        assert err["Code"] == "NotFoundException", (
            f"list_tags_for_resource on a deleted spending limit returned {err!r}, "
            "want NotFoundException"
        )
        assert err["Message"] == "Resource was not found", (
            f"list_tags_for_resource on a deleted spending limit: message {err['Message']!r}"
        )
        err = _client_error(
            lambda: braket.tag_resource(resourceArn=arn, tags={"sim2real-post-delete": "x"})
        )
        assert err["Code"] == "NotFoundException", (
            f"tag_resource on a deleted spending limit returned {err!r}, want NotFoundException"
        )
        assert err["Message"] == "Resource was not found", (
            f"tag_resource on a deleted spending limit: message {err['Message']!r}"
        )
    finally:
        if not deleted:
            ctx.on_cleanup(lambda: _best_effort_delete(braket, arn))


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _best_effort_delete(braket, arn) -> None:
    try:
        braket.delete_spending_limit(spendingLimitArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
