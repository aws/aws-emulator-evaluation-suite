"""grant-constraints-encryption-context-subset-round-trip."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "grant-constraints-encryption-context-subset-round-trip"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An EncryptionContextSubset grant constraint round-trips exactly through ListGrants.
    ListGrants is eventually consistent after CreateGrant, so visibility is polled with a bounded
    retry rather than assumed on the first read."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-grantctx-"),
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    grantee_arn = sts.get_caller_identity()["Arn"]
    constraints = {
        "EncryptionContextSubset": {
            "sim2real-purpose": "grant-constraint-check",
            "sim2real-env": "test",
        }
    }
    grant = kms.create_grant(
        KeyId=key_id,
        GranteePrincipal=grantee_arn,
        Operations=["Encrypt", "Decrypt"],
        Constraints=constraints,
    )
    grant_id = grant["GrantId"]
    ctx.on_cleanup(lambda: kms.revoke_grant(KeyId=key_id, GrantId=grant_id))

    found = _poll_until_visible(kms, key_id, grant_id, timeout_s=90.0)
    assert found is not None, f"grant {grant_id} never became visible via ListGrants"
    returned_constraints = found["Constraints"]
    assert returned_constraints == constraints, f"{returned_constraints} != {constraints}"


def _poll_until_visible(kms: Any, key_id: str, grant_id: str, timeout_s: float) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout_s
    while True:
        grants = kms.list_grants(KeyId=key_id, GrantId=grant_id)["Grants"]
        matches = [g for g in grants if g["GrantId"] == grant_id]
        assert len(matches) <= 1, f"expected at most one grant with id {grant_id}, got {matches}"
        if matches:
            return matches[0]
        if time.monotonic() >= deadline:
            return None
        time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
