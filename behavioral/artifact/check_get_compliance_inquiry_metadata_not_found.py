"""get-compliance-inquiry-metadata-not-found."""
from __future__ import annotations

import random
import string

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-compliance-inquiry-metadata-not-found"
GROUP = "error-semantics"
SERVICES = ["artifact"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetComplianceInquiryMetadata on a well-formed unknown id fails UnauthorizedException, not
    ResourceNotFoundException, while the same call on an owned inquiry succeeds."""
    art = ctx.client("artifact")
    name = ctx.unique_name("sim2real-artifact-getnotfound-")
    inquiry = _create_inquiry(ctx, name, "What is included in the AWS shared responsibility model?")
    inquiry_id = inquiry["id"]

    detail = art.get_compliance_inquiry_metadata(complianceInquiryId=inquiry_id)[
        "complianceInquiryDetail"
    ]
    assert detail["id"] == inquiry_id, f"positive control: expected {inquiry_id}, got {detail['id']}"

    fake_id = "compliance-inquiry-" + "".join(
        random.choices(string.ascii_letters + string.digits, k=16)
    )

    code, message = _error(lambda: art.get_compliance_inquiry_metadata(complianceInquiryId=fake_id))
    assert code == "UnauthorizedException", f"expected UnauthorizedException, got {code}"
    assert message == "Unauthorized", f"expected AWS's exact refusal message, got {message!r}"


def _create_inquiry(ctx, name, query_text, support_mode="AI_ONLY"):
    art = ctx.client("artifact")
    try:
        return art.create_compliance_inquiry(
            name=name,
            inquiryContent={"query": query_text},
            supportMode=support_mode,
        )["complianceInquirySummary"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            raise AssertionError(
                "account is not opted into AWS Artifact Assurance Assistant "
                "(CreateComplianceInquiry requires feature opt-in); cannot create a "
                "positive-control inquiry to prove the account can otherwise call "
                "GetComplianceInquiryMetadata"
            ) from e
        raise


def _error(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
