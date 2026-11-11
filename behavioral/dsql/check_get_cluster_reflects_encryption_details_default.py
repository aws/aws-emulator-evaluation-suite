"""get-cluster-reflects-encryption-details-default."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-cluster-reflects-encryption-details-default"
GROUP = "data-plane"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cluster created without a kmsEncryptionKey is encrypted with an AWS owned KMS key."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real-created-with": "get-cluster-reflects-encryption-details-default"},
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))

    got = dsql.get_cluster(identifier=identifier)
    details = got["encryptionDetails"]
    assert details["encryptionType"] == "AWS_OWNED_KMS_KEY", details["encryptionType"]
    assert details["encryptionStatus"] in ("ENABLED", "ENABLING"), details["encryptionStatus"]


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
