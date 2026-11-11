"""retire-grant."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "retire-grant"
GROUP = 'grants'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RetireGrant (by grant token) removes the grant."""
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    grantee = f"arn:aws:iam::{account_id}:root"
    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    resp = kms.create_grant(
        KeyId=key_id,
        GranteePrincipal=grantee,
        RetiringPrincipal=grantee,
        Operations=["Encrypt"],
    )
    grant_id = resp["GrantId"]
    grant_token = resp["GrantToken"]

    before = [g["GrantId"] for g in kms.list_grants(KeyId=key_id)["Grants"]]
    assert grant_id in before, f"grant {grant_id} must be listed before retirement: {before}"

    # Retire using the grant token
    kms.retire_grant(GrantToken=grant_token)
    grants = kms.list_grants(KeyId=key_id)["Grants"]
    found = [g["GrantId"] for g in grants]
    assert grant_id not in found, f"retired grant {grant_id} must not appear in ListGrants: {found}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
