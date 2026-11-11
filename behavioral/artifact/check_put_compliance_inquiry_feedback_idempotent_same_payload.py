"""put-compliance-inquiry-feedback-idempotent-same-payload."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-compliance-inquiry-feedback-idempotent-same-payload"
GROUP = "state"
SERVICES = ["artifact"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutComplianceInquiryFeedback called twice with the same clientToken and the
    same payload succeeds both times (idempotent retry), rather than conflicting with
    itself."""
    art = ctx.client("artifact")
    name = ctx.unique_name("sim2real-artifact-fbidem-")
    inquiry = _create_inquiry(ctx, name, "What is the retention period for CloudTrail logs?")
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
    assert len(queries) >= 1, f"expected at least one query on inquiry {inquiry_id}, got {queries!r}"
    query = queries[0]
    query_id = query["queryIdentifier"]
    revision_id = len(query.get("updatedResponseVersions") or [])

    token = ctx.unique_name("sim2real-fb-tok-")
    first = art.put_compliance_inquiry_feedback(
        complianceInquiryId=inquiry_id,
        queryIdentifier=query_id,
        rating="THUMBS_UP",
        responseRevisionId=revision_id,
        clientToken=token,
    )
    assert first["submittedAt"] is not None, f"expected a submittedAt timestamp, got {first!r}"

    second = art.put_compliance_inquiry_feedback(
        complianceInquiryId=inquiry_id,
        queryIdentifier=query_id,
        rating="THUMBS_UP",
        responseRevisionId=revision_id,
        clientToken=token,
    )
    # clientToken dedup means the retry is *ignored*, not reprocessed (per the
    # API's own documentation of clientToken), so the two responses must report
    # the identical submission -- not merely "both succeeded", which a target
    # that double-submits feedback on every retry would also satisfy.
    assert second["submittedAt"] == first["submittedAt"], (
        f"expected the idempotent retry to report the SAME submittedAt as the "
        f"first call (proving it was deduplicated, not reprocessed), got "
        f"first={first['submittedAt']!r} second={second['submittedAt']!r}"
    )


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
                "feedback idempotency"
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
