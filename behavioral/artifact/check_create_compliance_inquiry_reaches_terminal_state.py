"""create-compliance-inquiry-reaches-terminal-state."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-compliance-inquiry-reaches-terminal-state"
GROUP = "state"
SERVICES = ["artifact"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateComplianceInquiry starts an async workflow that transitions from
    PROCESSING to a terminal status (COMPLETED or FAILED), and the terminal detail
    still reflects the requested AI_ONLY supportMode and a valid status message."""
    art = ctx.client("artifact")
    # No ctx.on_cleanup: the artifact model has no delete operation for a compliance inquiry
    # (ComplianceInquiryResource exposes create/get/list/export/put-feedback only).
    name = ctx.unique_name("sim2real-artifact-terminal-")
    inquiry = _create_inquiry(ctx, name, "Summarize the AWS shared responsibility model.")
    inquiry_id = inquiry["id"]
    assert inquiry["status"] == "PROCESSING", f"expected initial status PROCESSING, got {inquiry['status']}"

    detail = _poll_until(
        lambda: art.get_compliance_inquiry_metadata(complianceInquiryId=inquiry_id)[
            "complianceInquiryDetail"
        ],
        lambda d: d["status"] in ("COMPLETED", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )

    assert detail["status"] in ("COMPLETED", "FAILED")
    assert detail["supportMode"] == "AI_ONLY"
    assert detail["id"] == inquiry_id
    # statusMessage must correlate with the terminal status actually reached: each message
    # in the InquiryStatusMessage enum names the status it belongs to (SUCCESS,
    # COMPLETED_WITH_ERRORS -> COMPLETED; INTERNAL_ERROR, MALWARE_DETECTED_ERROR -> FAILED),
    # so a terminal status paired with a non-terminal message (IN_PROGRESS,
    # HUMAN_REVIEW_IN_PROGRESS) is a real inconsistency, not just an unmodelled string.
    # A benign TEXT/AI_ONLY inquiry reaches COMPLETED with exactly
    # "Compliance inquiry processing is complete."
    _terminal_messages = {
        "COMPLETED": {
            "Compliance inquiry processing is complete.",
            "Compliance inquiry processing is complete. One or more queries encountered errors during processing.",
        },
        "FAILED": {
            "Malware was detected on the file. Provide a new file and try again.",
            "An internal error occurred while processing the inquiry. Try again at a later time.",
        },
    }
    assert detail["statusMessage"] in _terminal_messages[detail["status"]], (
        f"status {detail['status']!r} paired with statusMessage {detail['statusMessage']!r}, "
        f"expected one of {_terminal_messages[detail['status']]!r}"
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
                "the compliance-inquiry state machine"
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
