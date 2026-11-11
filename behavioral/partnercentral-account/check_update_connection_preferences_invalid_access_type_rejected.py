"""update-connection-preferences-invalid-access-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-connection-preferences-invalid-access-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-account"]


def _pca_client(ctx):
    """partnercentral-account is served only from us-east-1. ``region=`` pins that region while
    ctx.client keeps the runner's credentials and endpoint wiring; an emulator serves every
    region on one endpoint, so the same call is correct there."""
    return ctx.client("partnercentral-account", region="us-east-1")


def _update_prefs(pca, revision, access_type, excluded):
    """ExcludedParticipantIdentifiers must be OMITTED (real AWS: "must be null") for every
    AccessType other than ALLOW_BY_DEFAULT_DENY_SOME -- passing it as [] on DENY_ALL/ALLOW_ALL
    is itself a ValidationException, confirmed against real AWS (FieldValidationError,
    ExcludedParticipantIdentifiers, INVALID_VALUE)."""
    kwargs = {"Catalog": "AWS", "Revision": revision, "AccessType": access_type}
    if access_type == "ALLOW_BY_DEFAULT_DENY_SOME":
        kwargs["ExcludedParticipantIdentifiers"] = excluded
    return pca.update_connection_preferences(**kwargs)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:partnercentral-connection-preferences")
def run(ctx) -> None:
    """An AccessType outside the ALLOW_ALL/DENY_ALL/ALLOW_BY_DEFAULT_DENY_SOME enum is rejected
    with ValidationException and leaves Revision/AccessType untouched, while the same request
    with a valid AccessType (the only thing changed) succeeds."""
    pca = _pca_client(ctx)
    before = pca.get_connection_preferences(Catalog="AWS")
    original_access_type = before["AccessType"]
    original_excluded = before.get("ExcludedParticipantIds", [])
    revision = before["Revision"]

    def _revert() -> None:
        current = pca.get_connection_preferences(Catalog="AWS")
        _update_prefs(pca, current["Revision"], original_access_type, original_excluded)

    ctx.on_cleanup(_revert)

    error = _client_error(
        lambda: _update_prefs(pca, revision, "OPEN_TO_ALL_PARTNERS", original_excluded)
    )
    assert error.get("Code") == "ValidationException", (
        f"AccessType='OPEN_TO_ALL_PARTNERS' (outside the enum) was rejected with "
        f"{error.get('Code')!r}, expected 'ValidationException'"
    )
    assert error.get("Message") == (
        "1 validation error detected: Value at 'accessType' failed to satisfy constraint: Member "
        "must satisfy enum value set: [ALLOW_ALL, DENY_ALL, ALLOW_BY_DEFAULT_DENY_SOME]"
    ), error

    # Effect absent: rejected call did not advance Revision or change AccessType.
    unchanged = pca.get_connection_preferences(Catalog="AWS")
    assert unchanged["AccessType"] == original_access_type, (
        f"AccessType changed from {original_access_type!r} to {unchanged['AccessType']!r} "
        "across a rejected UpdateConnectionPreferences call"
    )
    assert unchanged["Revision"] == revision, (
        f"Revision advanced from {revision} to {unchanged['Revision']} across a rejected "
        "UpdateConnectionPreferences call"
    )

    # Positive control: same Revision, only the AccessType value fixed to a valid enum member.
    new_access_type = "DENY_ALL" if original_access_type != "DENY_ALL" else "ALLOW_ALL"
    _update_prefs(pca, revision, new_access_type, original_excluded)

    # Terminal read: independent of the mutating call's own response.
    after = pca.get_connection_preferences(Catalog="AWS")
    assert after["AccessType"] == new_access_type, (
        f"an independent read shows AccessType={after['AccessType']!r}, expected "
        f"{new_access_type!r} after the positive-control update"
    )
    assert after["Revision"] == revision + 1, (
        f"an independent read shows Revision={after['Revision']}, expected {revision + 1} "
        "after the positive-control update"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
