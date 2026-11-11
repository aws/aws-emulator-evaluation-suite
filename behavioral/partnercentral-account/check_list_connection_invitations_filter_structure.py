"""list-connection-invitations-filter-structure."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-connection-invitations-filter-structure"
GROUP = "control-plane"
SERVICES = ["partnercentral-account"]


def _pca_client(ctx):
    """partnercentral-account is served only from us-east-1. ``region=`` pins that region while
    ctx.client keeps the runner's credentials and endpoint wiring; an emulator serves every
    region on one endpoint, so the same call is correct there."""
    return ctx.client("partnercentral-account", region="us-east-1")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConnectionInvitations honors the ConnectionType and ParticipantType filters, and
    CreateConnectionInvitation to a receiver that names no real counterpart is refused, so the empty
    invitation list is the effect-absent leg of that refusal rather than a coincidence.
    """
    pca = _pca_client(ctx)

    # Positive control: creds and the service are otherwise healthy.
    pca.list_partners(Catalog="AWS")

    # The specific, deterministic refusal: CreateConnectionInvitation can never succeed from
    # here because no ReceiverIdentifier this check could supply names a real counterpart.
    try:
        pca.create_connection_invitation(
            Catalog="AWS",
            ClientToken=str(uuid.uuid4()),
            ConnectionType="OPPORTUNITY_COLLABORATION",
            Email="sim2real-unreachable@example.com",
            Message="sim2real audit probe -- expected to be rejected",
            Name="Sim2Real Audit",
            ReceiverIdentifier="partner-" + uuid.uuid4().hex[:13],
        )
        raise AssertionError("CreateConnectionInvitation unexpectedly succeeded with a fabricated receiver")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ValidationException", e.response["Error"]
        assert e.response["Error"]["Message"] == "1 validation error detected.", e.response["Error"]
        assert e.response.get("Reason") == "REQUEST_VALIDATION_FAILED", e.response
        assert e.response.get("ErrorDetails") == [
            {
                "FieldValidationError": {
                    "Name": "ReceiverIdentifier",
                    "Message": "Invalid receiver identifier for this connection type.",
                    "Code": "INVALID_VALUE",
                }
            }
        ], e.response.get("ErrorDetails")

    # Effect absent, via an independent read: the account has never held any invitation.
    by_type = pca.list_connection_invitations(Catalog="AWS", ConnectionType="OPPORTUNITY_COLLABORATION")
    summaries = by_type["ConnectionInvitationSummaries"]
    assert summaries == [], summaries
    for summary in summaries:
        assert summary["ConnectionType"] == "OPPORTUNITY_COLLABORATION", summary

    by_participant = pca.list_connection_invitations(Catalog="AWS", ParticipantType="SENDER")
    sender_summaries = by_participant["ConnectionInvitationSummaries"]
    assert sender_summaries == [], sender_summaries
    for summary in sender_summaries:
        assert summary["ParticipantType"] == "SENDER", summary


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
