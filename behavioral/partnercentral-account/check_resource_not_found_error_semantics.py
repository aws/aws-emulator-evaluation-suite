"""resource-not-found-error-semantics."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-not-found-error-semantics"
GROUP = "error-semantics"
SERVICES = ["partnercentral-account"]


def _pca_client(ctx):
    """partnercentral-account is served only from us-east-1. ``region=`` pins that region while
    ctx.client keeps the caller's credentials and endpoint wiring; an emulator serves every
    region on one endpoint, so the same call is correct there."""
    return ctx.client("partnercentral-account", region="us-east-1")


_PARTNER_BENEFIT_DENIED = (
    "This action requires an active AWS Partner benefit. Register as an AWS Partner if you "
    "haven't already, or contact AWS Partner Central Support."
)


def _error(fn):
    """Call fn(); return its Error dict plus the response's RequestId, or None on success."""
    try:
        fn()
        return None
    except ClientError as e:
        return {**e.response["Error"], "RequestId": e.response["ResponseMetadata"].get("RequestId")}


def _fake(prefix: str) -> str:
    return prefix + uuid.uuid4().hex[:13]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For well-formed, nonexistent identifiers under Catalog="AWS", partner-scoped operations fail with
    AccessDeniedException (no active partner benefit) before any lookup, while connection, invitation and
    verification operations fail with ResourceNotFoundException; GetConnectionPreferences succeeds.
    """
    pca = _pca_client(ctx)

    # Positive control: the credentials and region work before either contract is exercised.
    pca.get_connection_preferences(Catalog="AWS")

    partner_id = _fake("partner-")
    connection_id = _fake("pac-")
    invitation_id = _fake("pacinv-")
    task_id = _fake("pprofiletask-")
    token = lambda: str(uuid.uuid4())

    # Gated on this account's own AWS Partner enrollment, not on `partner_id`'s existence.
    partner_scoped_calls = [
        ("GetPartner", lambda: pca.get_partner(Catalog="AWS", Identifier=partner_id)),
        ("GetAllianceLeadContact", lambda: pca.get_alliance_lead_contact(Catalog="AWS", Identifier=partner_id)),
        ("GetProfileVisibility", lambda: pca.get_profile_visibility(Catalog="AWS", Identifier=partner_id)),
        (
            "GetQualificationsAssociationDetails",
            lambda: pca.get_qualifications_association_details(Catalog="AWS", Identifier=partner_id),
        ),
        ("GetProfileUpdateTask", lambda: pca.get_profile_update_task(Catalog="AWS", Identifier=partner_id)),
        (
            "GetQualificationsAssociationTask",
            lambda: pca.get_qualifications_association_task(Catalog="AWS", Identifier=partner_id),
        ),
        (
            "GetQualificationsDisassociationTask",
            lambda: pca.get_qualifications_disassociation_task(Catalog="AWS", Identifier=partner_id),
        ),
        (
            "PutAllianceLeadContact",
            lambda: pca.put_alliance_lead_contact(
                Catalog="AWS",
                Identifier=partner_id,
                AllianceLeadContact={
                    "FirstName": "Sim",
                    "LastName": "Real",
                    "Email": "sim2real-probe@example.com",
                    "BusinessTitle": "QA",
                },
            ),
        ),
        (
            "CancelProfileUpdateTask",
            lambda: pca.cancel_profile_update_task(Catalog="AWS", Identifier=partner_id, TaskId=task_id),
        ),
        (
            "DisassociateAwsTrainingCertificationEmailDomain",
            lambda: pca.disassociate_aws_training_certification_email_domain(
                Catalog="AWS", Identifier=partner_id, DomainName="example.com"
            ),
        ),
    ]

    # Resolve existence directly; no partner-membership gate sits in front of them. Each message
    # names the missing identifier; GetVerification's names the failing call's own request id.
    connection_missing = lambda _rid: (
        f"Connection not found with catalog: AWS and identifier: {connection_id}."
    )
    invitation_missing = lambda _rid: (
        f"Connection invitation not found with catalog: AWS and identifier: {invitation_id}."
    )
    verification_missing = lambda rid: (
        f"Verification not found for requestId: {rid}, accountId: {ctx.account} and "
        "verificationType: BUSINESS_VERIFICATION"
    )
    not_found_calls = [
        ("GetConnection", lambda: pca.get_connection(Catalog="AWS", Identifier=connection_id), connection_missing),
        (
            "GetConnectionInvitation",
            lambda: pca.get_connection_invitation(Catalog="AWS", Identifier=invitation_id),
            invitation_missing,
        ),
        (
            "GetVerification",
            lambda: pca.get_verification(VerificationType="BUSINESS_VERIFICATION"),
            verification_missing,
        ),
        (
            "CancelConnection",
            lambda: pca.cancel_connection(
                Catalog="AWS",
                Identifier=connection_id,
                ConnectionType="OPPORTUNITY_COLLABORATION",
                Reason="sim2real probe",
                ClientToken=token(),
            ),
            connection_missing,
        ),
        (
            "AcceptConnectionInvitation",
            lambda: pca.accept_connection_invitation(Catalog="AWS", Identifier=invitation_id, ClientToken=token()),
            invitation_missing,
        ),
        (
            "RejectConnectionInvitation",
            lambda: pca.reject_connection_invitation(Catalog="AWS", Identifier=invitation_id, ClientToken=token()),
            invitation_missing,
        ),
        (
            "CancelConnectionInvitation",
            lambda: pca.cancel_connection_invitation(Catalog="AWS", Identifier=invitation_id, ClientToken=token()),
            invitation_missing,
        ),
    ]

    failures = []
    for name, fn in partner_scoped_calls:
        error = _error(fn)
        code = error["Code"] if error else None
        message = error.get("Message", "") if error else ""
        if code != "AccessDeniedException" or message != _PARTNER_BENEFIT_DENIED:
            failures.append((name, "expected AccessDeniedException/partner-benefit denial", error))

    for name, fn, expected_message in not_found_calls:
        error = _error(fn)
        code = error["Code"] if error else None
        message = error.get("Message", "") if error else ""
        expected = expected_message(error["RequestId"]) if error else None
        if code != "ResourceNotFoundException" or message != expected:
            failures.append((name, f"expected ResourceNotFoundException/{expected!r}", error))

    assert not failures, f"got unexpected error shape(s): {failures}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
