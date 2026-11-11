"""create-cluster-with-initial-tags."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-cluster-with-initial-tags"
GROUP = "data-plane"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied inline on CreateCluster are persisted immediately and are visible via
    ListTagsForResource without any separate TagResource call."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real-created-with": "create-cluster", "sim2real-purpose": "behavioral-test"},
    )
    identifier = created["identifier"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: _best_effort_delete(dsql, identifier))

    tags = dsql.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("sim2real-created-with") == "create-cluster", (
        f"expected sim2real-created-with=create-cluster, got {tags.get('sim2real-created-with')!r} "
        f"in {tags!r}"
    )
    assert tags.get("sim2real-purpose") == "behavioral-test", (
        f"expected sim2real-purpose=behavioral-test, got {tags.get('sim2real-purpose')!r} in {tags!r}"
    )


def _best_effort_delete(dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
