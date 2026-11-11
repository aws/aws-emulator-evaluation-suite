"""put-compliance-inquiry-feedback-conflicting-payload-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-compliance-inquiry-feedback-conflicting-payload-rejected"
GROUP = "overly-permissive"
SERVICES = ["artifact"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a PutComplianceInquiryFeedback clientToken with a different rating fails
    ConflictException, while the same rating with a fresh token on another inquiry's revision
    succeeds (a revision accepts only one feedback)."""
    art = ctx.client("artifact")
    name = ctx.unique_name("sim2real-artifact-fbconflict-")
    inquiry = _create_inquiry(ctx, name, "Does AWS provide a HIPAA compliant offering?")
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
    assert len(queries) >= 1, f"expected at least one query for inquiry {inquiry_id}, got {queries!r}"
    query = queries[0]
    query_id = query["queryIdentifier"]
    revision_id = len(query.get("updatedResponseVersions") or [])

    reused_token = ctx.unique_name("sim2real-fb-reuse-")
    first = art.put_compliance_inquiry_feedback(
        complianceInquiryId=inquiry_id,
        queryIdentifier=query_id,
        rating="THUMBS_UP",
        responseRevisionId=revision_id,
        clientToken=reused_token,
    )
    assert first["submittedAt"] is not None, f"positive control: expected submittedAt, got {first!r}"

    code, message = _error(
        lambda: art.put_compliance_inquiry_feedback(
            complianceInquiryId=inquiry_id,
            queryIdentifier=query_id,
            rating="THUMBS_DOWN",
            responseRevisionId=revision_id,
            clientToken=reused_token,
        )
    )
    assert code == "ConflictException", f"expected ConflictException on token reuse with a different payload, got {code}"
    assert message == "Feedback already submitted for this response version.", (
        f"expected AWS's exact conflict message, got {message!r}"
    )

    # Positive control: a fresh clientToken submitting the same rating that conflicted
    # above, but against a *different* inquiry's revision (which has received no
    # feedback yet), succeeds -- proving THUMBS_DOWN itself isn't disallowed and the
    # earlier rejection was specifically about reusing a token with a changed payload
    # (or resubmitting on an already-fed-back revision), not the rating value.
    name2 = ctx.unique_name("sim2real-artifact-fbconflict2-")
    inquiry2 = _create_inquiry(ctx, name2, "Does AWS Artifact support GDPR compliance documentation?")
    inquiry2_id = inquiry2["id"]
    _poll_until(
        lambda: art.get_compliance_inquiry_metadata(complianceInquiryId=inquiry2_id)[
            "complianceInquiryDetail"
        ]["status"],
        lambda status: status in ("COMPLETED", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    queries2 = art.list_compliance_inquiry_queries(complianceInquiryId=inquiry2_id)["queries"]
    assert len(queries2) >= 1, f"expected at least one query for inquiry {inquiry2_id}, got {queries2!r}"
    query2 = queries2[0]
    query2_id = query2["queryIdentifier"]
    revision2_id = len(query2.get("updatedResponseVersions") or [])

    fresh_token = ctx.unique_name("sim2real-fb-fresh-")
    ok = art.put_compliance_inquiry_feedback(
        complianceInquiryId=inquiry2_id,
        queryIdentifier=query2_id,
        rating="THUMBS_DOWN",
        responseRevisionId=revision2_id,
        clientToken=fresh_token,
    )
    assert ok["submittedAt"] is not None, f"positive control on isolated revision: expected submittedAt, got {ok!r}"


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
                "feedback token-conflict semantics"
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


def _error(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
