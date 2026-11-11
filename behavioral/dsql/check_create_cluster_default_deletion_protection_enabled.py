"""create-cluster-default-deletion-protection-enabled."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-cluster-default-deletion-protection-enabled"
GROUP = "data-plane"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster defaults deletionProtectionEnabled to true when the field is omitted."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(
        tags={"sim2real-created-with": "create-cluster-default-deletion-protection-enabled"}
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))

    assert created["deletionProtectionEnabled"] is True, (
        f"CreateCluster with deletionProtectionEnabled omitted should default it to True, "
        f"got {created['deletionProtectionEnabled']!r}"
    )

    got = dsql.get_cluster(identifier=identifier)
    assert got["deletionProtectionEnabled"] is True, (
        f"GetCluster after CreateCluster (field omitted) should report deletionProtectionEnabled "
        f"True, got {got['deletionProtectionEnabled']!r}"
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
