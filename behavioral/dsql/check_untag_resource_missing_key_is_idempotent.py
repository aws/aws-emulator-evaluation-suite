"""untag-resource-missing-key-is-idempotent."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "untag-resource-missing-key-is-idempotent"
GROUP = "data-plane"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with a tag key that isn't attached succeeds as a no-op rather than erroring."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(deletionProtectionEnabled=False, tags={"sim2real-kept": "yes"})
    identifier = created["identifier"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))

    # "sim2real-never-set" was never attached to this cluster.
    dsql.untag_resource(resourceArn=arn, tagKeys=["sim2real-never-set"])

    tags = dsql.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("sim2real-kept") == "yes", "unrelated tag was disturbed by the no-op untag"
    assert "sim2real-never-set" not in tags, f"key was never attached but appears in tags: {tags!r}"


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
