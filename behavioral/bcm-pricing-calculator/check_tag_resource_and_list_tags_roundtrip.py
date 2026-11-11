"""tag-resource-and-list-tags-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-roundtrip"
GROUP = "tagging"
SERVICES = ["bcm-pricing-calculator"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a WorkloadEstimate is reflected exactly by ListTagsForResource."""
    client = ctx.client("bcm-pricing-calculator")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-we-")

    estimate_id = client.create_workload_estimate(name=name)["id"]
    ctx.on_cleanup(lambda: _delete_workload_estimate(client, estimate_id))
    arn = _arn(account_id, "workload-estimate", estimate_id)

    client.tag_resource(arn=arn, tags={"sim2real-env": "test", "sim2real-owner": "sim2real"})

    tags = client.list_tags_for_resource(arn=arn)["tags"]
    assert tags == {"sim2real-env": "test", "sim2real-owner": "sim2real"}, (
        f"expected both tags from the multi-key TagResource call, got {tags!r}"
    )

    # A second TagResource call adds a tag; it must merge with the existing set, not replace it.
    client.tag_resource(arn=arn, tags={"sim2real-team": "fidelity"})
    merged = client.list_tags_for_resource(arn=arn)["tags"]
    assert merged == {
        "sim2real-env": "test",
        "sim2real-owner": "sim2real",
        "sim2real-team": "fidelity",
    }, f"expected the second TagResource call to merge with the existing tags, got {merged!r}"


# ===== helpers =====
def _arn(account_id, resource_type, resource_id):
    return f"arn:aws:bcm-pricing-calculator::{account_id}:{resource_type}/{resource_id}"


def _delete_workload_estimate(client, estimate_id):
    from botocore.exceptions import ClientError

    try:
        client.delete_workload_estimate(identifier=estimate_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
