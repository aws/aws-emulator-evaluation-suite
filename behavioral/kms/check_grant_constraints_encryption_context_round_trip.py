"""grant-constraints-encryption-context-round-trip."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "grant-constraints-encryption-context-round-trip"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode values in a grant's EncryptionContextEquals constraint persist exactly as written,
    read back via ListGrants (which is eventually consistent after CreateGrant)."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    root_arn = f"arn:aws:iam::{account_id}:root"

    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-grantctx-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    context_constraint = {
        "tenant-\U0001f511": "acme-\u65e5\u672c\u8a9e",
        "region/path with slash": "va&lue=1;m\u00f6re",
    }

    grant = kms.create_grant(
        KeyId=key_id,
        GranteePrincipal=root_arn,
        Operations=["Encrypt", "Decrypt"],
        Constraints={"EncryptionContextEquals": context_constraint},
    )
    grant_id = grant["GrantId"]
    ctx.on_cleanup(lambda: kms.revoke_grant(KeyId=key_id, GrantId=grant_id))

    found = _poll_until_grant(ctx, key_id, grant_id, timeout_s=90.0)
    assert found is not None, f"grant {grant_id} never became visible via ListGrants"
    round_tripped = found["Constraints"]["EncryptionContextEquals"]
    assert round_tripped == context_constraint, (
        f"EncryptionContextEquals did not round-trip: expected {context_constraint!r}, got {round_tripped!r}"
    )


def _poll_until_grant(ctx, key_id: str, grant_id: str, timeout_s: float = 90.0) -> dict[str, Any] | None:
    kms = ctx.client("kms")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = kms.list_grants(KeyId=key_id)
        for g in resp.get("Grants", []):
            if g["GrantId"] == grant_id:
                return g
        time.sleep(3.0)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
