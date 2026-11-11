"""create-list-grant."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "create-list-grant"
GROUP = 'grants'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGrant + ListGrants returns the grant with correct principal and operations."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    # A well-known, always-valid principal so this check needs no extra IAM setup — KMS validates
    # that GranteePrincipal refers to a real principal at CreateGrant time.
    grantee = f"arn:aws:iam::{account_id}:root"
    resp = kms.create_grant(
        KeyId=key_id,
        GranteePrincipal=grantee,
        Operations=["Encrypt", "Decrypt"],
    )
    grant_id = resp["GrantId"]
    assert "GrantToken" in resp, f"expected a GrantToken in CreateGrant response, got keys {sorted(resp)}"

    # List grants for this key — an independent read at a different operation than the mutation
    grants = kms.list_grants(KeyId=key_id)["Grants"]
    found = [g for g in grants if g["GrantId"] == grant_id]
    assert len(found) == 1, f"expected exactly 1 grant with id {grant_id} in ListGrants, found {len(found)}"
    assert found[0]["GranteePrincipal"] == grantee, (
        f"expected GranteePrincipal {grantee!r}, got {found[0]['GranteePrincipal']!r}"
    )
    assert set(found[0]["Operations"]) == {"Encrypt", "Decrypt"}, (
        f"expected Operations {{'Encrypt', 'Decrypt'}}, got {set(found[0]['Operations'])}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
