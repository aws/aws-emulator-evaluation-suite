"""add-profile-permission-concurrent-revision-conflict."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "add-profile-permission-concurrent-revision-conflict"
GROUP = "concurrency"
SERVICES = ["signer"]

LAMBDA_PLATFORM = "AWSLambda-SHA384-ECDSA"
RACER_COUNT = 5


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N racers using the same optimistic revisionId: exactly one AddProfilePermission wins."""
    signer = ctx.client("signer")
    name = _profile_name(ctx, "racerev")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))
    principal_account = ctx.client("sts").get_caller_identity()["Account"]
    signer.put_signing_profile(
        profileName=name,
        platformId=LAMBDA_PLATFORM,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )

    seed_rev = signer.add_profile_permission(
        profileName=name,
        action="signer:GetSigningProfile",
        principal=principal_account,
        statementId="sim2real-seed",
    )["revisionId"]

    def racer(idx: int):
        try:
            resp = signer.add_profile_permission(
                profileName=name,
                action="signer:GetSigningProfile",
                principal=principal_account,
                statementId=f"sim2real-race-{idx}",
                revisionId=seed_rev,
            )
            return ("ok", idx, resp["revisionId"])
        except Exception as exc:  # noqa: BLE001 - classify below
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return ("error", idx, exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            raise

    with ThreadPoolExecutor(max_workers=RACER_COUNT) as pool:
        results = list(pool.map(racer, range(RACER_COUNT)))

    successes = [r for r in results if r[0] == "ok"]
    conflicts = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly one winner, got {results!r}"
    assert len(conflicts) == RACER_COUNT - 1, (
        f"expected {RACER_COUNT - 1} conflicts, got {len(conflicts)}: {results!r}"
    )
    assert all(code == "ConflictException" for _, _, code, _ in conflicts), (
        f"expected every loser to report ConflictException, got {conflicts!r}"
    )

    _, winner_idx, winner_rev = successes[0]
    # A loser names the revision it found current: the winner's, or the seed's while the
    # winning write is still landing.
    stale = f"Specified revisionId ({seed_rev}) does not match the revisionId of the existing policy"
    for _, _, _, message in conflicts:
        current = winner_rev if (message or "").endswith(f"({winner_rev})") else seed_rev
        assert message == f"{stale} ({current})", (
            f"expected the loser message to name {seed_rev!r} against the current revision, "
            f"got {message!r}"
        )

    # The policy reflects exactly the seed statement plus the single winning racer's statement,
    # and the winner's own reported revisionId is what the independent read now sees current.
    winner_statement_id = f"sim2real-race-{winner_idx}"
    listed = signer.list_profile_permissions(profileName=name)
    statement_ids = {p["statementId"] for p in listed["permissions"]}
    assert statement_ids == {"sim2real-seed", winner_statement_id}, (
        f"expected {{'sim2real-seed', {winner_statement_id!r}}}, got {statement_ids!r}"
    )
    assert listed["revisionId"] == winner_rev, (
        f"expected current revisionId {winner_rev!r} (from the winning racer's own response), "
        f"got {listed['revisionId']!r}"
    )


def _profile_name(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-signer-{kind}-").replace("-", "_")


def _cancel_quietly(signer, profile_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        signer.cancel_signing_profile(profileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
