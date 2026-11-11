"""partner-profile-reflects-completed-update-task."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partner-profile-reflects-completed-update-task"
GROUP = "error-semantics"
SERVICES = ["partnercentral-account"]

# Uses the Sandbox catalog. See:
# https://docs.aws.amazon.com/partner-central/latest/developer-guide/testing-sandbox-account.html
#
# NAME-VS-BODY MISMATCH (intentional): a profile-update task targets a Sandbox Partner, and
# CreatePartner -- the only way to obtain one -- is refused deterministically while the linked
# account has not completed AWS Partner Central's Know-Your-Business (KYB) and
# Identity-Verification (IDV) checks; no API completes either, so the refusal is the asserted
# contract.


def _pca_client(ctx):
    """partnercentral-account is served only from us-east-1. ``region=`` pins that region while
    ctx.client keeps the runner's credentials and endpoint wiring; an emulator serves every
    region on one endpoint, so the same call is correct there."""
    return ctx.client("partnercentral-account", region="us-east-1")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePartner, the only way to obtain the Sandbox Partner a profile update task targets, is
    rejected with ValidationException/BUSINESS_VALIDATION_FAILED for an account without KYB and IDV,
    after a ListPartners positive control, and leaves no Partner behind."""
    pca = _pca_client(ctx)

    before = pca.list_partners(Catalog="Sandbox")["PartnerSummaryList"]
    assert before == [], f"expected no Sandbox partner yet (positive control), found {before}"

    try:
        pca.create_partner(
            Catalog="Sandbox",
            ClientToken=str(uuid.uuid4()),
            LegalName="Sim2Real Partner " + uuid.uuid4().hex[:8],
            PrimarySolutionType="SOFTWARE_PRODUCTS",
            AllianceLeadContact={
                "FirstName": "Sim",
                "LastName": "Tester",
                "Email": f"sim2real-{uuid.uuid4().hex[:8]}@example.com",
                "BusinessTitle": "QA Engineer",
            },
            EmailVerificationCode="123456",
        )
        raise AssertionError("CreatePartner unexpectedly succeeded -- the KYB/IDV gate has been lifted")
    except ClientError as e:
        resp = e.response
        assert resp["Error"]["Code"] == "ValidationException", (
            f"expected ValidationException, got {resp['Error']['Code']}"
        )
        assert resp["Error"]["Message"] == "2 validation errors detected.", resp["Error"]
        assert resp.get("Reason") == "BUSINESS_VALIDATION_FAILED", (
            f"expected Reason BUSINESS_VALIDATION_FAILED, got {resp.get('Reason')}"
        )
        assert resp.get("ErrorDetails") == [
            {
                "BusinessValidationError": {
                    "Message": "The AWS account did not complete Know Your Business (KYB) verification.",
                    "Code": "INCOMPATIBLE_KNOW_YOUR_BUSINESS_STATUS",
                }
            },
            {
                "BusinessValidationError": {
                    "Message": "The AWS account did not complete Identity Verification (IDV).",
                    "Code": "INCOMPATIBLE_IDENTITY_VERIFICATION_STATUS",
                }
            },
        ], resp.get("ErrorDetails")

    # Effect absent: the rejected CreatePartner left nothing behind.
    after = pca.list_partners(Catalog="Sandbox")["PartnerSummaryList"]
    assert after == [], f"expected still no Sandbox partner after the rejected create, found {after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
