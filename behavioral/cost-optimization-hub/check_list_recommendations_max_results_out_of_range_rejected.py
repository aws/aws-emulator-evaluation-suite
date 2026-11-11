"""list-recommendations-max-results-out-of-range-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-recommendations-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["cost-optimization-hub"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment")
def run(ctx) -> None:
    """ListRecommendations rejects a maxResults value above the documented [0,1000] range,
    while the maximum in-range value in the same call shape still succeeds."""
    # cost-optimization-hub is served only from us-east-1; pin it there for both targets via
    # ctx.client()'s region override, which keeps the check's own credentials (a bare
    # boto3.client() here would resolve the ambient chain instead).
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    # ListRecommendations requires the account to be enrolled -- an unenrolled account gets
    # AccessDeniedException before its input is even validated, which masks the maxResults
    # contract this check exists to test. Enroll (idempotent, restored on cleanup) first.
    # A freshly provisioned account has no enrollment record at all (empty `items`) until the
    # first UpdateEnrollmentStatus call ever made against it -- that absence IS "Inactive".
    existing = coh.list_enrollment_statuses()["items"]
    original_status = existing[0]["status"] if existing else "Inactive"
    ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_status))
    coh.update_enrollment_status(status="Active")
    _poll_until(
        lambda: coh.list_enrollment_statuses()["items"][0],
        lambda item: item["status"] == "Active",
        timeout_s=30.0,
    )

    response = _client_error(lambda: coh.list_recommendations(maxResults=1001))
    code = response["Error"]["Code"]
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    message = response["Error"].get("Message", "")
    expected_message = "Input validation failed. Please check the field list for more details."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"
    expected_fields = [
        {"fieldName": "maxResults", "message": "Member must have value less than or equal to 1000"}
    ]
    assert response.get("fields") == expected_fields, (
        f"expected fields {expected_fields!r}, got {response.get('fields')!r}"
    )

    # Positive control: the boundary value itself is accepted.
    control = coh.list_recommendations(maxResults=1000)
    assert isinstance(control["items"], list), f"expected a list, got {control['items']!r}"


# ===== helpers =====
def _client_error(fn):
    """Call fn(); return its botocore error response. An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS rejects must not be reported as a
    plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
