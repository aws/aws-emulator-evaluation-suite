"""grant-with-constraints."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "grant-with-constraints"
GROUP = 'grants'
SERVICES = ['kms']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGrant with an EncryptionContextSubset constraint is stored and reflected correctly:
    an independent ListGrants call — not CreateGrant's own response — must return the exact
    constraint."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    key = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms, key_id))

    grantee_arn = sts.get_caller_identity()["Arn"]
    constraints = {"EncryptionContextSubset": {"department": "engineering"}}
    grant = kms.create_grant(
        KeyId=key_id,
        GranteePrincipal=grantee_arn,
        Operations=["Encrypt", "Decrypt"],
        Constraints=constraints,
    )
    grant_id = grant["GrantId"]
    ctx.on_cleanup(lambda: _safe_revoke_grant(kms, key_id, grant_id))

    grants = kms.list_grants(KeyId=key_id, GrantId=grant_id)["Grants"]
    found = [g for g in grants if g["GrantId"] == grant_id]
    assert len(found) == 1, f"expected exactly one grant {grant_id} in ListGrants, found {len(found)}"
    stored_constraints = found[0].get("Constraints", {})
    assert stored_constraints == constraints, (
        f"expected Constraints {constraints!r} to round-trip through ListGrants, "
        f"got {stored_constraints!r}"
    )


def _safe_revoke_grant(kms, key_id: str, grant_id: str | None) -> None:
    if not grant_id:
        return
    try:
        kms.revoke_grant(KeyId=key_id, GrantId=grant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_schedule_delete(client, key_id: str) -> None:
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
