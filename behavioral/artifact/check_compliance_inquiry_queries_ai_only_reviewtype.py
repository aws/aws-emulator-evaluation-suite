"""compliance-inquiry-queries-ai-only-reviewtype."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "compliance-inquiry-queries-ai-only-reviewtype"
GROUP = "state"
SERVICES = ["artifact"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """For an inquiry created with supportMode=AI_ONLY, every query under it reaches a
    terminal status and is reviewed by AI, never HUMAN -- FULL_SUPPORT-only behavior
    must not leak into an AI_ONLY inquiry."""
    art = ctx.client("artifact")
    name = ctx.unique_name("sim2real-artifact-reviewtype-")
    inquiry = _create_inquiry(ctx, name, "List the AWS regions covered by the PCI DSS attestation.")
    inquiry_id = inquiry["id"]

    _poll_until(
        lambda: art.get_compliance_inquiry_metadata(complianceInquiryId=inquiry_id)[
            "complianceInquiryDetail"
        ]["status"],
        lambda status: status in ("COMPLETED", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )

    queries = art.list_compliance_inquiry_queries(complianceInquiryId=inquiry_id)["queries"]
    assert len(queries) >= 1, "expected at least one query under the inquiry"
    for q in queries:
        assert q["status"] in ("COMPLETED", "FAILED"), q
        assert q["reviewType"] == "AI", f"AI_ONLY inquiry produced a non-AI reviewType: {q['reviewType']}"


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
                "(CreateComplianceInquiry requires feature opt-in); cannot exercise "
                "the query reviewType semantics"
            ) from e
        raise


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
