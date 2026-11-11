"""update-connection-preferences-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-connection-preferences-round-trip"
GROUP = "state"
SERVICES = ["partnercentral-account"]


def _pca_client(ctx):
    """partnercentral-account is served only from us-east-1. ``region=`` pins that region while
    ctx.client keeps the runner's credentials and endpoint wiring; an emulator serves every
    region on one endpoint, so the same call is correct there."""
    return ctx.client("partnercentral-account", region="us-east-1")


def _update_kwargs(revision, access_type, excluded):
    """Real AWS rejects this call with ValidationException/REQUEST_VALIDATION_FAILED
    ("ExcludedParticipantIdentifiers must be null for AccessType DENY_ALL") when the field is
    present -- even as an empty list -- for ALLOW_ALL/DENY_ALL. It is only accepted (and only
    meaningful) for ALLOW_BY_DEFAULT_DENY_SOME, so omit it entirely otherwise."""
    kwargs = {"Catalog": "AWS", "Revision": revision, "AccessType": access_type}
    if access_type == "ALLOW_BY_DEFAULT_DENY_SOME":
        kwargs["ExcludedParticipantIdentifiers"] = excluded
    return kwargs


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:partnercentral-connection-preferences",
)
def run(ctx) -> None:
    """UpdateConnectionPreferences persists the new AccessType and monotonically bumps Revision;
    GetConnectionPreferences immediately reflects the write (strong read-after-write, not eventual)."""
    pca = _pca_client(ctx)
    before = pca.get_connection_preferences(Catalog="AWS")
    original_access_type = before["AccessType"]
    original_excluded = before.get("ExcludedParticipantIds", [])
    original_revision = before["Revision"]

    new_access_type = "DENY_ALL" if original_access_type != "DENY_ALL" else "ALLOW_ALL"

    def _revert() -> None:
        current = pca.get_connection_preferences(Catalog="AWS")
        pca.update_connection_preferences(
            **_update_kwargs(current["Revision"], original_access_type, original_excluded)
        )

    ctx.on_cleanup(_revert)

    updated = pca.update_connection_preferences(
        **_update_kwargs(original_revision, new_access_type, original_excluded)
    )
    assert updated["AccessType"] == new_access_type, (
        f"expected AccessType {new_access_type!r}, got {updated['AccessType']!r}"
    )
    assert updated["Revision"] == original_revision + 1, (
        f"expected Revision {original_revision + 1}, got {updated['Revision']!r}"
    )

    after = pca.get_connection_preferences(Catalog="AWS")
    assert after["AccessType"] == new_access_type, (
        f"independent read: expected AccessType {new_access_type!r}, got {after['AccessType']!r}"
    )
    assert after["Revision"] == original_revision + 1, (
        f"independent read: expected Revision {original_revision + 1}, got {after['Revision']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
