"""create-cluster-tags-reflected-in-get-cluster."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-cluster-tags-reflected-in-get-cluster"
GROUP = "data-plane"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied at CreateCluster are persisted and visible via GetCluster and ListTagsForResource."""
    dsql = ctx.client("dsql")
    marker = ctx.unique_name("sim2real-dsql-tagval-")
    tags = {"sim2real-purpose": marker}
    created = dsql.create_cluster(deletionProtectionEnabled=False, tags=tags)
    identifier = created["identifier"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))

    got = dsql.get_cluster(identifier=identifier)
    got_tag = got.get("tags", {}).get("sim2real-purpose")
    assert got_tag == marker, f"GetCluster tags.sim2real-purpose: expected {marker!r}, got {got_tag!r}"

    listed = dsql.list_tags_for_resource(resourceArn=arn)
    listed_tag = listed.get("tags", {}).get("sim2real-purpose")
    assert listed_tag == marker, (
        f"ListTagsForResource tags.sim2real-purpose: expected {marker!r}, got {listed_tag!r}"
    )


def _delete_cluster(ctx, identifier):
    from botocore.exceptions import ClientError

    dsql = ctx.client("dsql")
    try:
        dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
