"""create-grant-concurrent-same-params-distinct-grants."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "create-grant-concurrent-same-params-distinct-grants"
GROUP = "concurrency"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateGrant calls with identical grantee, Operations and Name return the
    same GrantId (Name-based idempotency), and ListGrants lists that grant exactly once."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    grantee_arn = sts.get_caller_identity()["Arn"]

    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsgrant-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-create-grant-concurrent-same-params-distinct-grants"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    grant_name = ctx.unique_name("sim2real-behav-grantname-")

    def _create() -> str:
        resp = kms.create_grant(
            KeyId=key_id,
            GranteePrincipal=grantee_arn,
            Operations=["Encrypt"],
            Name=grant_name,
        )
        return resp["GrantId"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_1 = pool.submit(_create)
        fut_2 = pool.submit(_create)
        grant_id_1 = fut_1.result()
        grant_id_2 = fut_2.result()

    ctx.on_cleanup(lambda: kms.revoke_grant(KeyId=key_id, GrantId=grant_id_1))

    assert grant_id_1 == grant_id_2, (
        "expected two concurrent CreateGrant calls with identical Name/grantee/operations "
        f"to be idempotent and resolve to the same GrantId, but got {grant_id_1!r} and "
        f"{grant_id_2!r}"
    )

    listed_ids = [g["GrantId"] for g in kms.list_grants(KeyId=key_id)["Grants"]]
    assert listed_ids.count(grant_id_1) == 1, (
        f"expected exactly one grant entry for the idempotent GrantId in ListGrants, "
        f"got {listed_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

