"""create-repository-link-with-kms-encryption-key-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-repository-link-with-kms-encryption-key-round-trip"
GROUP = "data-plane"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRepositoryLink with an EncryptionKeyArn stores and returns that KMS key ARN unchanged."""
    cc = ctx.client("codestar-connections")
    kms = ctx.client("kms")

    key_arn = kms.create_key(
        Description="sim2real codestar-connections behavioral check key",
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]
    key_id = key_arn.split("/")[-1]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    conn_arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-cn-")[:32],
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, conn_arn))

    owner = ctx.unique_name("sim2real-owner-")
    repo = ctx.unique_name("sim2real-repo-")
    resp = cc.create_repository_link(
        ConnectionArn=conn_arn,
        OwnerId=owner,
        RepositoryName=repo,
        EncryptionKeyArn=key_arn,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    info = resp["RepositoryLinkInfo"]
    link_id = info["RepositoryLinkId"]
    ctx.on_cleanup(lambda: _safe_delete_repository_link(cc, link_id))

    assert info["EncryptionKeyArn"] == key_arn, (
        f"CreateRepositoryLink response EncryptionKeyArn: expected {key_arn!r}, "
        f"got {info.get('EncryptionKeyArn')!r}"
    )

    got = cc.get_repository_link(RepositoryLinkId=link_id)["RepositoryLinkInfo"]
    assert got["EncryptionKeyArn"] == key_arn, (
        f"GetRepositoryLink EncryptionKeyArn: expected {key_arn!r}, got {got.get('EncryptionKeyArn')!r}"
    )


def _safe_delete_connection(cc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_connection(ConnectionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_repository_link(cc, link_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_repository_link(RepositoryLinkId=link_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
