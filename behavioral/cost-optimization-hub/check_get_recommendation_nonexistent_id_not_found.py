"""get-recommendation-nonexistent-id-not-found."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "get-recommendation-nonexistent-id-not-found"
GROUP = "error-semantics"
SERVICES = ["cost-optimization-hub"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment")
def run(ctx) -> None:
    """GetRecommendation for a well-formed but non-existent recommendationId returns
    ResourceNotFoundException, while a real, currently-listed recommendation (if any)
    still resolves successfully in the same call shape."""
    # region="us-east-1": Cost Optimization Hub's API is served only from us-east-1;
    # ctx.client(region=...) keeps the check's own credentials, which a bare
    # boto3.client(...) would bypass.
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    # GetRecommendation on an unenrolled account answers AccessDeniedException
    # regardless of id, so enrollment is a real
    # prerequisite for the not-found contract this check exists to prove, not an
    # optional nicety. Create-or-adopt: only flip and only restore what we flipped.
    existing = coh.list_enrollment_statuses().get("items", [])
    original_status = existing[0]["status"] if existing else "Inactive"
    if original_status != "Active":
        ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_status))
        coh.update_enrollment_status(status="Active")
        _poll_until(
            lambda: coh.list_enrollment_statuses()["items"][0],
            lambda item: item["status"] == "Active",
            timeout_s=30.0,
        )

    bogus_id = str(uuid.uuid4())
    response = _client_error(lambda: coh.get_recommendation(recommendationId=bogus_id))
    code = response["Error"]["Code"]
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent recommendationId, got {code!r}"
    )
    # AWS sends no message for this error, only the echoed resourceId.
    message = response["Error"].get("Message", "")
    assert message == "", f"expected no error message, got {message!r}"
    assert response.get("resourceId") == bogus_id, (
        f"expected resourceId {bogus_id!r} echoed in the error, got {response.get('resourceId')!r}"
    )

    # Positive control, opportunistic: if the account happens to have a live
    # recommendation, fetching it must still succeed (proves the rejection above is
    # about THIS id, not the operation being universally broken/blocked).
    listed = coh.list_recommendations(maxResults=1).get("items", [])
    if listed:
        detail = coh.get_recommendation(recommendationId=listed[0]["recommendationId"])
        assert detail["recommendationId"] == listed[0]["recommendationId"], (
            f"GetRecommendation on a currently-listed id returned a different id: "
            f"expected {listed[0]['recommendationId']!r}, got {detail['recommendationId']!r}"
        )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
