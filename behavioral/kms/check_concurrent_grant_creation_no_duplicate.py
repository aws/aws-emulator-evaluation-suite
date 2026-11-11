"""concurrent-grant-creation-no-duplicate."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-grant-creation-no-duplicate"
GROUP = "concurrency"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent identical CreateGrant calls (no Name) on one key each mint a distinct GrantId,
    and ListGrants lists exactly those grants: KMS does not dedupe unnamed grant creation."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    # A well-known, always-valid principal so this check needs no extra IAM setup.
    grantee_principal = f"arn:aws:iam::{account_id}:root"

    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-grant-race-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-concurrent-grant-creation-no-duplicate"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    n_racers = 8

    def _create_grant(_i: int) -> str:
        resp = kms.create_grant(
            KeyId=key_id,
            GranteePrincipal=grantee_principal,
            Operations=["Decrypt", "Encrypt"],
        )
        return resp["GrantId"]

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(_create_grant, i) for i in range(n_racers)]
        grant_ids = [f.result() for f in as_completed(futures)]

    for gid in grant_ids:
        ctx.on_cleanup(lambda gid=gid: kms.revoke_grant(KeyId=key_id, GrantId=gid))

    assert len(grant_ids) == n_racers, f"expected {n_racers} grant creations, got {len(grant_ids)}"
    assert len(set(grant_ids)) == n_racers, (
        f"CreateGrant returned duplicate GrantIds under concurrency: {grant_ids}"
    )

    listed_ids: set[str] = set()
    marker = None
    while True:
        kwargs = {"KeyId": key_id}
        if marker:
            kwargs["Marker"] = marker
        page = kms.list_grants(**kwargs)
        for g in page.get("Grants", []):
            listed_ids.add(g["GrantId"])
        if not page.get("Truncated"):
            break
        marker = page.get("NextMarker")

    assert set(grant_ids).issubset(listed_ids), (
        "some concurrently created grants never showed up in ListGrants: "
        f"missing={set(grant_ids) - listed_ids}"
    )
    assert len(listed_ids) == n_racers, (
        f"ListGrants shows {len(listed_ids)} grants on a fresh key, expected exactly {n_racers} "
        "(no dedup, no corruption/loss)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
