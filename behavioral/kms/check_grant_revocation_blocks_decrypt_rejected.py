"""grant-revocation-blocks-decrypt-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "grant-revocation-blocks-decrypt-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After RevokeGrant, the grant leaves ListGrants and Decrypt with its GrantToken fails, within 900 s, with
    AccessDeniedException and the exact message, while a new grant for the same caller decrypts the same
    ciphertext (KMS documents token revocation can take several minutes)."""
    from botocore.exceptions import ClientError


    kms = ctx.client("kms")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    caller_arn = identity["Arn"]
    root_arn = f"arn:aws:iam::{account_id}:root"

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AdminActionsOnly",
                "Effect": "Allow",
                "Principal": {"AWS": root_arn},
                "Action": [
                    "kms:CreateGrant",
                    "kms:RevokeGrant",
                    "kms:ListGrants",
                    "kms:DescribeKey",
                    "kms:Encrypt",
                    "kms:PutKeyPolicy",
                    "kms:GetKeyPolicy",
                    "kms:ScheduleKeyDeletion",
                ],
                "Resource": "*",
            }
        ],
    }
    key_meta = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Policy=json.dumps(policy),
        Description=ctx.unique_name("sim2real-kms-revoke-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-grant-revocation"}],
    )["KeyMetadata"]
    key_id, key_arn = key_meta["KeyId"], key_meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    plaintext = b"grant-revocation-plaintext"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]

    grant = kms.create_grant(KeyId=key_id, GranteePrincipal=caller_arn, Operations=["Decrypt"])
    grant_id = grant["GrantId"]
    grant_token = grant["GrantToken"]

    # Positive control: the grant genuinely authorizes Decrypt before revocation.
    decrypted = kms.decrypt(
        KeyId=key_id, CiphertextBlob=ciphertext, GrantTokens=[grant_token]
    )["Plaintext"]
    assert decrypted == plaintext, (
        f"positive control: Decrypt with an active GrantToken returned {decrypted!r}, "
        f"expected {plaintext!r}"
    )

    kms.revoke_grant(KeyId=key_id, GrantId=grant_id)

    # Effect-absent: the grant is gone from ListGrants (bounded poll for the
    # documented eventual-consistency window: accessing-kms.html#programming-
    # eventual-consistency -- "typically less than a few seconds ... in some
    # cases several minutes").
    deadline = time.monotonic() + 60
    gone = False
    while time.monotonic() < deadline:
        grants = kms.list_grants(KeyId=key_id)["Grants"]
        if not any(g["GrantId"] == grant_id for g in grants):
            gone = True
            break
        time.sleep(5)
    assert gone, "revoked grant never disappeared from ListGrants within 60s"

    # Decrypt with the revoked GrantToken must eventually be rejected. AWS documents this lag
    # as "in some cases several minutes"; poll for the refusal for up to 900s rather than
    # assume it is immediate.
    def _probe():
        kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext, GrantTokens=[grant_token])

    deadline = time.monotonic() + 900
    rejected_code = rejected_message = None
    while time.monotonic() < deadline:
        try:
            _probe()
        except ClientError as err:
            rejected_code = err.response["Error"]["Code"]
            rejected_message = err.response["Error"].get("Message")
            break
        time.sleep(2)
    assert rejected_code == "AccessDeniedException", (
        f"expected Decrypt with the revoked GrantToken to fail AccessDeniedException "
        f"within 900s, got {rejected_code!r}"
    )
    assert rejected_message == (
        f"User: {caller_arn} is not authorized to perform: kms:Decrypt on resource: {key_arn} "
        f"because no resource-based policy allows the kms:Decrypt action"
    ), f"unexpected message: {rejected_message!r}"

    # Positive control #2: a brand-new grant on the same key/caller still works,
    # proving the rejection above is specific to the revoked grant, not a blanket
    # deny of this operation.
    grant2 = kms.create_grant(KeyId=key_id, GranteePrincipal=caller_arn, Operations=["Decrypt"])
    ctx.on_cleanup(lambda: kms.revoke_grant(KeyId=key_id, GrantId=grant2["GrantId"]))
    decrypted2 = kms.decrypt(
        KeyId=key_id, CiphertextBlob=ciphertext, GrantTokens=[grant2["GrantToken"]]
    )["Plaintext"]
    assert decrypted2 == plaintext, (
        f"positive control #2: Decrypt with a fresh GrantToken on the same key/caller "
        f"returned {decrypted2!r}, expected {plaintext!r} -- the earlier rejection must "
        f"be specific to the revoked grant, not a blanket deny"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
