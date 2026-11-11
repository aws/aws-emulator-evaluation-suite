"""concurrent-grant-revoke-double-revoke-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "concurrent-grant-revoke-double-revoke-rejected"
GROUP = "concurrency"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two racing RevokeGrant calls on one grant: at least one succeeds, any loser fails with
    NotFoundException, and the grant stays gone. An uncontended RevokeGrant removes its grant."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    grantee_principal = f"arn:aws:iam::{account_id}:root"

    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-grant-double-revoke-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # --- positive control: a single grant is created and revoked cleanly ---
    control_grant_id = kms.create_grant(
        KeyId=key_id, GranteePrincipal=grantee_principal, Operations=["Decrypt"]
    )["GrantId"]
    kms.revoke_grant(KeyId=key_id, GrantId=control_grant_id)
    remaining = {g["GrantId"] for g in kms.list_grants(KeyId=key_id).get("Grants", [])}
    assert control_grant_id not in remaining, (
        "positive control: grant is still listed after a normal, uncontended RevokeGrant"
    )

    # --- the race: two concurrent revokes of the SAME grant ---
    race_grant_id = kms.create_grant(
        KeyId=key_id, GranteePrincipal=grantee_principal, Operations=["Decrypt"]
    )["GrantId"]

    def _revoke_once() -> tuple[str, dict | None]:
        err = _client_error(lambda: kms.revoke_grant(KeyId=key_id, GrantId=race_grant_id))
        return ("error", err) if err else ("ok", None)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _revoke_once(), range(2)))

    outcomes = [r[0] for r in results]
    # RevokeGrant is eventually consistent (Smithy RevokeGrant docs), so both racers may win.
    assert outcomes.count("ok") in (1, 2), (
        f"expected one or two winning RevokeGrant calls out of the racing pair, got {outcomes}"
    )
    errors = [r[1] for r in results if r[0] == "error"]
    assert len(errors) in (1, 0), f"expected at most one rejected RevokeGrant, got {results}"
    for err in errors:
        assert err["Code"] == "NotFoundException", (
            f"the losing concurrent RevokeGrant must fail NotFoundException, got {err}"
        )
        expected = f"Grant ID {race_grant_id} not found"
        assert err["Message"] == expected, f"expected message {expected!r}, got {err}"

    remaining_after = {g["GrantId"] for g in kms.list_grants(KeyId=key_id).get("Grants", [])}
    assert race_grant_id not in remaining_after, (
        "the raced grant is still present after being revoked -- it must not be resurrected"
    )


def _client_error(fn: Callable[[], Any]) -> dict | None:
    """Invoke fn(); return the ClientError's error on failure, else None."""
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
