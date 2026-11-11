"""revoke-grant."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "revoke-grant"
GROUP = 'grants'
SERVICES = ['kms']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RevokeGrant removes the grant from ListGrants."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    account = sts.get_caller_identity()["Account"]
    grantee = f"arn:aws:iam::{account}:root"
    resp = kms.create_grant(
        KeyId=key_id,
        GranteePrincipal=grantee,
        Operations=["Encrypt"],
    )
    grant_id = resp["GrantId"]

    kms.revoke_grant(KeyId=key_id, GrantId=grant_id)
    grants = kms.list_grants(KeyId=key_id)["Grants"]
    found = [g for g in grants if g["GrantId"] == grant_id]
    assert len(found) == 0, f"expected grant {grant_id} absent from ListGrants after revoke, found {found}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
