"""update-connection-preferences-concurrent-writers."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-connection-preferences-concurrent-writers"
GROUP = "concurrency"
SERVICES = ["partnercentral-account"]


def _pca_client(ctx):
    """partnercentral-account is served only from us-east-1. ``region=`` pins that region while
    ctx.client keeps the caller's credentials and endpoint wiring; an emulator serves every
    region on one endpoint, so the same call is correct there."""
    return ctx.client("partnercentral-account", region="us-east-1")


def _update_kwargs(catalog, revision, access_type, excluded):
    """Real AWS rejects ExcludedParticipantIdentifiers outright (ValidationException,
    "ExcludedParticipantIdentifiers must be null for AccessType <X>") for any AccessType
    other than ALLOW_BY_DEFAULT_DENY_SOME -- even an explicit empty list, which is not the
    same as the field being absent. Only include it for that one AccessType."""
    kwargs = {"Catalog": catalog, "Revision": revision, "AccessType": access_type}
    if access_type == "ALLOW_BY_DEFAULT_DENY_SOME":
        kwargs["ExcludedParticipantIdentifiers"] = excluded
    return kwargs


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:partnercentral-connection-preferences",
)
def run(ctx) -> None:
    """Concurrent UpdateConnectionPreferences calls on the same Revision let exactly one writer win (Revision
    advances by exactly 1), and every loser fails with ConflictException naming the winner's new Revision.
    """
    pca = _pca_client(ctx)
    before = pca.get_connection_preferences(Catalog="AWS")
    original_access_type = before["AccessType"]
    original_excluded = before.get("ExcludedParticipantIds", [])
    revision = before["Revision"]

    def _revert() -> None:
        current = pca.get_connection_preferences(Catalog="AWS")
        pca.update_connection_preferences(
            **_update_kwargs("AWS", current["Revision"], original_access_type, original_excluded)
        )

    ctx.on_cleanup(_revert)

    racer_access_type = "DENY_ALL" if original_access_type != "DENY_ALL" else "ALLOW_ALL"

    def _racer(_i: int):
        try:
            resp = pca.update_connection_preferences(
                **_update_kwargs("AWS", revision, racer_access_type, original_excluded)
            )
            return ("ok", resp["Revision"])
        except ClientError as e:
            err = e.response["Error"]
            return ("err", err["Code"], err.get("Message", ""))

    n_racers = 5
    results = []
    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(_racer, i) for i in range(n_racers)]
        for f in as_completed(futures):
            results.append(f.result())

    wins = [r for r in results if r[0] == "ok"]
    losses = [r for r in results if r[0] == "err"]

    assert len(wins) == 1, f"expected exactly 1 winner, got {len(wins)}: {results}"
    assert len(losses) == n_racers - 1

    # ConflictException carries no `Reason` field for a revision mismatch -- the Message text is
    # the only evidence, and it names the exact revision numbers on both sides of the mismatch.
    conflict_message = (
        f"Revision mismatch for catalog AWS and account {ctx.account}. "
        f"Expected Revision: {revision + 1}, Provided Revision: {revision}."
    )
    for loss in losses:
        assert loss[1] == "ConflictException", loss
        assert loss[2] == conflict_message, loss

    assert wins[0][1] == revision + 1

    after = pca.get_connection_preferences(Catalog="AWS")
    assert after["Revision"] == revision + 1
    assert after["AccessType"] == racer_access_type


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
