"""update-connection-preferences-stale-revision-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-connection-preferences-stale-revision-rejected"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-account"]


def _pca_client(ctx):
    """partnercentral-account is served only from us-east-1. ``region=`` pins that region while
    ctx.client keeps the caller's credentials and endpoint wiring; an emulator serves every
    region on one endpoint, so the same call is correct there."""
    return ctx.client("partnercentral-account", region="us-east-1")


def _error_info(fn):
    """Call fn(); return its botocore Error code/message. An unexpected SUCCESS raises, because a
    target that ACCEPTS a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects a stale-Revision UpdateConnectionPreferences, but it SUCCEEDED and "
        f"returned {result!r}"
    )


def _update(pca, *, catalog, revision, access_type, excluded):
    """Call UpdateConnectionPreferences, omitting ExcludedParticipantIdentifiers unless it is set.

    AWS rejects ExcludedParticipantIdentifiers with ValidationException/REQUEST_VALIDATION_FAILED
    ("ExcludedParticipantIdentifiers must be null for AccessType DENY_ALL") for any AccessType other
    than ALLOW_BY_DEFAULT_DENY_SOME, including an empty list, a rule the model does not express.
    """
    kwargs = {"Catalog": catalog, "Revision": revision, "AccessType": access_type}
    if access_type == "ALLOW_BY_DEFAULT_DENY_SOME":
        kwargs["ExcludedParticipantIdentifiers"] = excluded
    return pca.update_connection_preferences(**kwargs)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:partnercentral-connection-preferences",
)
def run(ctx) -> None:
    """UpdateConnectionPreferences with a superseded Revision fails with ConflictException whose message names
    the expected and provided Revisions, and leaves the state unchanged, while the same change with the current
    Revision succeeds.
    """
    pca = _pca_client(ctx)
    before = pca.get_connection_preferences(Catalog="AWS")
    original_access_type = before["AccessType"]
    original_excluded = before.get("ExcludedParticipantIds", [])
    stale_revision = before["Revision"]

    def _revert() -> None:
        current = pca.get_connection_preferences(Catalog="AWS")
        _update(
            pca,
            catalog="AWS",
            revision=current["Revision"],
            access_type=original_access_type,
            excluded=original_excluded,
        )

    ctx.on_cleanup(_revert)

    # Positive control: a legitimate write with the correct current Revision succeeds and
    # advances the Revision, which makes `stale_revision` genuinely stale.
    intermediate_access_type = "DENY_ALL" if original_access_type != "DENY_ALL" else "ALLOW_ALL"
    control = _update(
        pca,
        catalog="AWS",
        revision=stale_revision,
        access_type=intermediate_access_type,
        excluded=original_excluded,
    )
    assert control["Revision"] == stale_revision + 1, (
        f"expected control write to advance Revision to {stale_revision + 1}, got "
        f"{control['Revision']!r}"
    )
    assert control["AccessType"] == intermediate_access_type, (
        f"expected control write to set AccessType={intermediate_access_type!r}, got "
        f"{control['AccessType']!r}"
    )

    # Break exactly one thing: reuse the stale Revision.
    other_access_type = "ALLOW_ALL" if intermediate_access_type != "ALLOW_ALL" else "DENY_ALL"
    code, message = _error_info(
        lambda: _update(
            pca,
            catalog="AWS",
            revision=stale_revision,
            access_type=other_access_type,
            excluded=original_excluded,
        )
    )
    assert code == "ConflictException", f"expected code=ConflictException, got {code!r}"
    # `Reason` is unpopulated on this exception, so the specific cause comes from `Message`: it
    # names the exact expected (current) and provided (stale) Revisions.
    assert message == (
        f"Revision mismatch for catalog AWS and account {ctx.account}. "
        f"Expected Revision: {stale_revision + 1}, Provided Revision: {stale_revision}."
    ), message

    # Effect absent: the state from the rejected call never landed.
    after = pca.get_connection_preferences(Catalog="AWS")
    assert after["AccessType"] == intermediate_access_type, (
        f"rejected call must not change AccessType; expected {intermediate_access_type!r}, "
        f"got {after['AccessType']!r}"
    )
    assert after["Revision"] == stale_revision + 1, (
        f"rejected call must not advance Revision; expected {stale_revision + 1}, got "
        f"{after['Revision']!r}"
    )

    # Restore: the stale Revision itself can never become valid again, but the SAME intended
    # change (other_access_type), retried with the current Revision, must succeed -- proving
    # the rejection was about optimistic concurrency, not the operation itself.
    restored = _update(
        pca,
        catalog="AWS",
        revision=after["Revision"],
        access_type=other_access_type,
        excluded=original_excluded,
    )
    assert restored["AccessType"] == other_access_type, (
        f"expected restore write to set AccessType={other_access_type!r}, got "
        f"{restored['AccessType']!r}"
    )
    assert restored["Revision"] == stale_revision + 2, (
        f"expected restore write to advance Revision to {stale_revision + 2}, got "
        f"{restored['Revision']!r}"
    )

    # Terminal read: independent GET at the destination confirms the restored write landed.
    final = pca.get_connection_preferences(Catalog="AWS")
    assert final["AccessType"] == other_access_type, (
        f"expected final AccessType={other_access_type!r}, got {final['AccessType']!r}"
    )
    assert final["Revision"] == stale_revision + 2, (
        f"expected final Revision={stale_revision + 2}, got {final['Revision']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
