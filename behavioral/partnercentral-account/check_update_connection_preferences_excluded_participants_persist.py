"""update-connection-preferences-excluded-participants-persist."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-connection-preferences-excluded-participants-persist"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-account"]


def _pca_client(ctx):
    """partnercentral-account is served only from us-east-1. ``region=`` pins that region while
    ctx.client keeps the caller's credentials and endpoint wiring; an emulator serves every
    region on one endpoint, so the same call is correct there."""
    return ctx.client("partnercentral-account", region="us-east-1")


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:partnercentral-connection-preferences",
)
def run(ctx) -> None:
    """UpdateConnectionPreferences rejects every ExcludedParticipantIdentifiers value tried with
    ValidationException/REQUEST_VALIDATION_FAILED and INVALID_VALUE on that field, leaving AccessType, Revision
    and the exclusions unchanged, while a plain AccessType change succeeds.
    """
    pca = _pca_client(ctx)
    before = pca.get_connection_preferences(Catalog="AWS")
    original_access_type = before["AccessType"]
    original_excluded = before.get("ExcludedParticipantIds", [])
    original_revision = before["Revision"]

    def _revert() -> None:
        # ExcludedParticipantIdentifiers must be omitted for any AccessType but
        # ALLOW_BY_DEFAULT_DENY_SOME; AWS rejects even an empty list there.
        current = pca.get_connection_preferences(Catalog="AWS")
        kwargs = {"Catalog": "AWS", "Revision": current["Revision"], "AccessType": original_access_type}
        if original_access_type == "ALLOW_BY_DEFAULT_DENY_SOME":
            kwargs["ExcludedParticipantIdentifiers"] = original_excluded
        pca.update_connection_preferences(**kwargs)

    ctx.on_cleanup(_revert)

    # Positive control: a plain AccessType change with no excluded ids succeeds and bumps
    # Revision by exactly 1 -- the account and credentials are otherwise healthy.
    control_type = "DENY_ALL" if original_access_type != "DENY_ALL" else "ALLOW_ALL"
    control = pca.update_connection_preferences(
        Catalog="AWS", Revision=original_revision, AccessType=control_type
    )
    assert control["AccessType"] == control_type, control
    assert control["Revision"] == original_revision + 1, control

    # The specific refusal: any ExcludedParticipantIdentifiers value is rejected on this
    # account, because it references no partner-network participant real AWS can validate
    # against.
    excluded_id = "acct" + uuid.uuid4().hex[:12]
    try:
        pca.update_connection_preferences(
            Catalog="AWS",
            Revision=control["Revision"],
            AccessType="ALLOW_BY_DEFAULT_DENY_SOME",
            ExcludedParticipantIdentifiers=[excluded_id],
        )
        raise AssertionError("expected ValidationException; UpdateConnectionPreferences succeeded")
    except ClientError as e:
        err = e.response["Error"]
        assert err["Code"] == "ValidationException", err
        assert err["Message"] == "1 validation error detected.", err
        assert e.response.get("Reason") == "REQUEST_VALIDATION_FAILED", e.response
        assert e.response.get("ErrorDetails") == [
            {
                "FieldValidationError": {
                    "Name": "ExcludedParticipantIdentifiers",
                    "Message": "At least 1 value provided in ExcludedParticipantIdentifiers is invalid.",
                    "Code": "INVALID_VALUE",
                }
            }
        ], e.response.get("ErrorDetails")

    # Effect absent: the rejected call did not advance Revision or touch AccessType/exclusions.
    after = pca.get_connection_preferences(Catalog="AWS")
    assert after["AccessType"] == control_type, after
    assert after["Revision"] == control["Revision"], after
    assert after.get("ExcludedParticipantIds", []) == original_excluded, after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
