"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "tagging"
SERVICES = ["bcm-pricing-calculator"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the requested key; ListTagsForResource no longer reports it
    while an untouched sibling tag survives."""
    client = ctx.client("bcm-pricing-calculator")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-we-")

    estimate_id = client.create_workload_estimate(name=name)["id"]
    ctx.on_cleanup(lambda: _delete_workload_estimate(client, estimate_id))
    arn = _arn(account_id, "workload-estimate", estimate_id)

    client.tag_resource(arn=arn, tags={"sim2real-key": "v1", "sim2real-keep": "kept"})
    before = client.list_tags_for_resource(arn=arn)["tags"]
    assert before == {"sim2real-key": "v1", "sim2real-keep": "kept"}, before

    client.untag_resource(arn=arn, tagKeys=["sim2real-key"])

    # Selective removal: only the requested key is gone, the untouched one survives.
    after = client.list_tags_for_resource(arn=arn)["tags"]
    assert after == {"sim2real-keep": "kept"}, after


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
