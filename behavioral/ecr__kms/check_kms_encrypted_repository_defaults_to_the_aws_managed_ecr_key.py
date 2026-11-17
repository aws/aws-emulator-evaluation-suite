"""kms-encrypted-repository-defaults-to-the-aws-managed-ecr-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kms-encrypted-repository-defaults-to-the-aws-managed-ecr-key"
GROUP = "server-side"
SERVICES = ["ecr", "kms"]

_KEY_PROPAGATION_TIMEOUT_S = 30.0


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_repo_once_key_is_usable(ecr, **kwargs):
    """CreateRepository, retrying while a just-created KMS key has not yet propagated to ECR."""
    deadline = time.monotonic() + _KEY_PROPAGATION_TIMEOUT_S
    while True:
        try:
            return ecr.create_repository(**kwargs)["repository"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsException" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A KMS-encrypted repository with no kmsKey uses the AWS managed key alias/aws/ecr,
    not a key the caller supplied, and a customer key stays distinct from it.

    Reference: https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html
    """
    ecr = ctx.client("ecr")
    kms = ctx.client("kms")

    managed_key = kms.describe_key(KeyId="alias/aws/ecr")["KeyMetadata"]
    assert managed_key["KeyManager"] == "AWS", (
        f"alias/aws/ecr resolves to a key with KeyManager {managed_key.get('KeyManager')!r}, "
        f"expected 'AWS' (a caller never owns this key)"
    )
    managed_arn = managed_key["Arn"]

    default_repo = ctx.unique_name("sim2real-xsvc-ecr-kms-default-")
    created = ecr.create_repository(
        repositoryName=default_repo,
        encryptionConfiguration={"encryptionType": "KMS"},
        tags=[{"Key": "sim2real", "Value": "ecr-kms-default-key"}],
    )["repository"]
    ctx.on_cleanup(
        _teardown(
            lambda: ecr.delete_repository(repositoryName=default_repo, force=True),
            "RepositoryNotFoundException",
        )
    )
    assert created["encryptionConfiguration"]["encryptionType"] == "KMS", (
        f"CreateRepository echoed encryptionConfiguration "
        f"{created.get('encryptionConfiguration')!r}, expected encryptionType 'KMS'"
    )
    assert created["encryptionConfiguration"]["kmsKey"] == managed_arn, (
        f"CreateRepository with no kmsKey reports kmsKey "
        f"{created['encryptionConfiguration'].get('kmsKey')!r}; kms:DescribeKey resolves "
        f"alias/aws/ecr to {managed_arn!r}. A repository given no key must use that managed one"
    )

    described = ecr.describe_repositories(repositoryNames=[default_repo])["repositories"][0]
    assert described["encryptionConfiguration"]["kmsKey"] == managed_arn, (
        f"DescribeRepositories reports kmsKey {described['encryptionConfiguration'].get('kmsKey')!r} "
        f"for a repository created with no kmsKey, expected the managed key {managed_arn!r} that "
        f"CreateRepository itself reported"
    )

    customer_key = kms.create_key(
        Description="sim2real: customer CMK that must stay distinct from the AWS managed ECR key",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "ecr-kms-default-key-control"}],
    )["KeyMetadata"]
    customer_key_id, customer_key_arn = customer_key["KeyId"], customer_key["Arn"]
    ctx.on_cleanup(
        _teardown(
            lambda: kms.schedule_key_deletion(KeyId=customer_key_id, PendingWindowInDays=7),
            "NotFoundException",
        )
    )
    assert customer_key_arn != managed_arn, (
        f"a freshly created customer CMK {customer_key_arn!r} is the same key as the AWS managed "
        f"alias/aws/ecr key {managed_arn!r}; the two must never collide"
    )

    customer_repo = ctx.unique_name("sim2real-xsvc-ecr-kms-customer-")
    customer_created = _create_repo_once_key_is_usable(
        ecr,
        repositoryName=customer_repo,
        encryptionConfiguration={"encryptionType": "KMS", "kmsKey": customer_key_arn},
        tags=[{"Key": "sim2real", "Value": "ecr-kms-default-key-control"}],
    )
    ctx.on_cleanup(
        _teardown(
            lambda: ecr.delete_repository(repositoryName=customer_repo, force=True),
            "RepositoryNotFoundException",
        )
    )
    assert customer_created["encryptionConfiguration"]["kmsKey"] == customer_key_arn, (
        f"a repository given an explicit kmsKey reports "
        f"{customer_created['encryptionConfiguration'].get('kmsKey')!r} instead of the key supplied, "
        f"{customer_key_arn!r}; the explicit key must not fall back to the managed one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
