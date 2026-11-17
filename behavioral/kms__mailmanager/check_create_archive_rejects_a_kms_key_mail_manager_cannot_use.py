"""create-archive-rejects-a-kms-key-mail-manager-cannot-use."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-archive-rejects-a-kms-key-mail-manager-cannot-use"
GROUP = "archive-encryption"
SERVICES = ["kms", "mailmanager"]


def _client_error(fn: Any) -> tuple[str, str]:
    """``fn``'s ``(Error.Code, Error.Message)``. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_kms_key(ctx: Any, *, grant_mailmanager: bool) -> str:
    """A customer managed key; ``grant_mailmanager`` adds the policy statement that lets Mail
    Manager use it to encrypt an archive, omitted leaves only the account's own root access."""
    kms = ctx.client("kms")
    statements = [
        {
            "Sid": "EnableRootFullAccess",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
            "Action": "kms:*",
            "Resource": "*",
        },
    ]
    if grant_mailmanager:
        statements.append({
            "Sid": "AllowMailManagerToUseTheKey",
            "Effect": "Allow",
            "Principal": {"Service": "ses.amazonaws.com"},
            "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
            "Resource": "*",
        })
    policy = {"Version": "2012-10-17", "Statement": statements}
    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-mm-kms-"),
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-mailmanager-behavioral"}],
    )["KeyMetadata"]["KeyId"]

    def _schedule_delete() -> None:
        try:
            kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_schedule_delete)
    return f"arn:aws:kms:{ctx.region}:{ctx.account}:key/{key_id}"


def _create_archive_with_key_policy_retry(
    mm: Any, name: str, key_arn: str, *, budget_s: float = 60.0, poll_s: float = 3.0
) -> str:
    """CreateArchive, retrying the exact transient Mail Manager raises while a fresh key
    policy propagates -- never a different code or message."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            return mm.create_archive(ArchiveName=name, KmsKeyArn=key_arn)["ArchiveId"]
        except ClientError as exc:
            error = exc.response["Error"]
            if (error["Code"], error.get("Message")) != ("AccessDeniedException", "Unable to use KMS key"):
                raise
            assert time.monotonic() < deadline, f"key policy did not propagate within {budget_s}s"
            time.sleep(poll_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateArchive resolves KmsKeyArn against the real key: it rejects one naming no key at
    all and one whose policy does not authorize Mail Manager, and accepts one that does.

    Reference: https://docs.aws.amazon.com/ses/latest/dg/encryption-rest.html
    """
    mm = ctx.client("mailmanager")

    bogus_key_arn = f"arn:aws:kms:{ctx.region}:{ctx.account}:key/00000000-0000-0000-0000-000000000000"
    bad_name = ctx.unique_name("sim2real-behav-mm-arc-bad-")
    code, message = _client_error(
        lambda: mm.create_archive(ArchiveName=bad_name, KmsKeyArn=bogus_key_arn)
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    assert message == "Unable to use KMS key", f"expected 'Unable to use KMS key', got {message!r}"

    pages = mm.get_paginator("list_archives").paginate()
    names = [a["ArchiveName"] for page in pages for a in page["Archives"]]
    assert bad_name not in names, (
        f"expected {bad_name!r} absent after the rejected create, found it in {names!r}"
    )

    # A key that exists and that our own account can use, but whose policy never authorizes
    # Mail Manager, is refused the identical way: the ARN resolves, the permission does not.
    unauthorized_key_arn = _create_kms_key(ctx, grant_mailmanager=False)
    unauthorized_name = ctx.unique_name("sim2real-behav-mm-arc-unauth-")
    code, message = _client_error(
        lambda: mm.create_archive(ArchiveName=unauthorized_name, KmsKeyArn=unauthorized_key_arn)
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    assert message == "Unable to use KMS key", f"expected 'Unable to use KMS key', got {message!r}"

    pages = mm.get_paginator("list_archives").paginate()
    names = [a["ArchiveName"] for page in pages for a in page["Archives"]]
    assert unauthorized_name not in names, (
        f"expected {unauthorized_name!r} absent after the rejected create, found it in {names!r}"
    )

    key_arn = _create_kms_key(ctx, grant_mailmanager=True)
    good_name = ctx.unique_name("sim2real-behav-mm-arc-good-")
    archive_id = _create_archive_with_key_policy_retry(mm, good_name, key_arn)
    ctx.on_cleanup(lambda: mm.delete_archive(ArchiveId=archive_id))

    got = mm.get_archive(ArchiveId=archive_id)
    assert got["KmsKeyArn"] == key_arn, (
        f"expected GetArchive KmsKeyArn {key_arn!r}, got {got['KmsKeyArn']!r}"
    )
    assert got["ArchiveState"] == "ACTIVE", f"expected ArchiveState ACTIVE, got {got['ArchiveState']!r}"

    mm.delete_archive(ArchiveId=archive_id)
    after = mm.get_archive(ArchiveId=archive_id)
    assert after["ArchiveState"] == "PENDING_DELETION", (
        f"expected ArchiveState PENDING_DELETION after delete, got {after['ArchiveState']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
