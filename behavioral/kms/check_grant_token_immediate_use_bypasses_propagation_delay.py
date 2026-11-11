"""grant-token-immediate-use-bypasses-propagation-delay."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "grant-token-immediate-use-bypasses-propagation-delay"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A fresh GrantToken authorizes Decrypt immediately for a caller the key policy denies,
    bypassing grant propagation delay; ListGrants eventually shows the grant too."""
    from botocore.exceptions import ClientError

    kms = ctx.client("kms")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    caller_arn = identity["Arn"]
    root_arn = f"arn:aws:iam::{account_id}:root"

    # The key policy omits kms:Decrypt, so only an explicit grant can permit Decrypt.
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
        Description=ctx.unique_name("sim2real-kms-granttoken-"),
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id, key_arn = key_meta["KeyId"], key_meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    plaintext = b"grant-token-immediate-use-plaintext"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]

    def _decrypt_no_grant():
        kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext)

    try:
        _decrypt_no_grant()
        raise AssertionError("Decrypt succeeded for a caller with no key-policy Decrypt grant")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
        message = err.response["Error"].get("Message")
        assert message == (
            f"User: {caller_arn} is not authorized to perform: kms:Decrypt on resource: {key_arn} "
            f"because no resource-based policy allows the kms:Decrypt action"
        ), f"unexpected message: {message!r}"

    grant = kms.create_grant(
        KeyId=key_id,
        GranteePrincipal=caller_arn,
        Operations=["Decrypt"],
    )
    grant_id = grant["GrantId"]
    grant_token = grant["GrantToken"]
    ctx.on_cleanup(lambda: kms.revoke_grant(KeyId=key_id, GrantId=grant_id))

    # No sleep here on purpose: the GrantToken must authorize this immediately,
    # not after the grant becomes independently visible via ListGrants.
    decrypted = kms.decrypt(
        KeyId=key_id, CiphertextBlob=ciphertext, GrantTokens=[grant_token]
    )["Plaintext"]
    assert decrypted == plaintext, f"expected round-tripped plaintext {plaintext!r}, got {decrypted!r}"

    # Grants are eventually consistent; allow up to 60 s to appear in ListGrants.
    deadline = time.monotonic() + 60
    seen = False
    while time.monotonic() < deadline:
        grants = kms.list_grants(KeyId=key_id)["Grants"]
        if any(g["GrantId"] == grant_id for g in grants):
            seen = True
            break
        time.sleep(3)
    assert seen, "grant never appeared in ListGrants within 60s"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
