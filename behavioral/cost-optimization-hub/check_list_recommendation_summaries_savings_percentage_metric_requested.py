"""list-recommendation-summaries-savings-percentage-metric-requested."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-recommendation-summaries-savings-percentage-metric-requested"
GROUP = "data-plane"
SERVICES = ["cost-optimization-hub"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:cost-optimization-hub-enrollment", "resource:account-singleton:cost-optimization-hub-preferences")
def run(ctx) -> None:
    """For a member account without discount visibility, UpdatePreferences(AfterDiscounts) is refused
    with a specific ValidationException and changes nothing, and the savingsPercentage metric
    filtered by accountId returns the "not supported ... before discounts" sentence, not a number."""
    # cost-optimization-hub is served only from us-east-1; pin it there for both targets via
    # ctx.client()'s region override, which keeps the check's own credentials (a bare
    # boto3.client() here would resolve the ambient chain instead).
    coh = ctx.client("cost-optimization-hub", region="us-east-1")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # ListRecommendationSummaries requires the account to be enrolled -- an unenrolled account
    # gets AccessDeniedException before the metrics request is even evaluated. Enroll (idempotent,
    # restored on cleanup) first. A freshly provisioned account has no enrollment record at all
    # (empty `items`) until the first UpdateEnrollmentStatus call ever made against it -- that
    # absence IS "Inactive".
    existing_enrollment = coh.list_enrollment_statuses()["items"]
    original_status = existing_enrollment[0]["status"] if existing_enrollment else "Inactive"
    ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_status))
    coh.update_enrollment_status(status="Active")
    _poll_until(
        lambda: coh.list_enrollment_statuses()["items"][0],
        lambda item: item["status"] == "Active",
        timeout_s=30.0,
    )

    original_preferences = coh.get_preferences()
    ctx.on_cleanup(lambda: _restore_preferences(coh, original_preferences))
    original_mode = original_preferences.get("savingsEstimationMode")

    if original_mode == "AfterDiscounts":
        # An account that already carries the org-level grant: the number itself is the contract.
        resp = coh.list_recommendation_summaries(
            groupBy="ResourceType",
            filter={"accountIds": [account_id]},
            metrics=["SavingsPercentage"],
        )
        raw = resp.get("metrics", {}).get("savingsPercentage")
        assert isinstance(raw, str) and len(raw) > 0, f"expected a non-empty string, got {raw!r}"
        value = float(raw)
        assert value >= 0.0, f"expected a non-negative percentage, got {value!r}"
        return

    # Positive control: the account and credentials are otherwise healthy for this service --
    # an enrolled account can list its own summaries at all.
    control = coh.list_recommendation_summaries(
        groupBy="ResourceType", filter={"accountIds": [account_id]}
    )
    assert isinstance(control.get("items"), list), f"expected a list, got {control.get('items')!r}"

    # The specific refusal: AfterDiscounts needs an org-level grant this member account lacks.
    code, message = _error_code_and_message(
        lambda: coh.update_preferences(savingsEstimationMode="AfterDiscounts")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "Invalid permission to update preferences. To use AfterDiscounts savings estimation mode, "
        "the management account must either enable member account discount visibility in Cost "
        "Optimization Hub, or enable linked account discount visibility in Cost Management "
        "Preferences."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect-absent: the refused update left the stored preference untouched.
    unchanged = coh.get_preferences().get("savingsEstimationMode")
    assert unchanged == original_mode, (
        f"expected savingsEstimationMode to stay {original_mode!r} after the refused update, "
        f"got {unchanged!r}"
    )

    # The documented consequence: under a mode that is not AfterDiscounts, the requested
    # savingsPercentage metric is the exact sentinel string, not a number.
    resp = coh.list_recommendation_summaries(
        groupBy="ResourceType",
        filter={"accountIds": [account_id]},
        metrics=["SavingsPercentage"],
    )
    raw = resp.get("metrics", {}).get("savingsPercentage")
    expected_sentinel = (
        "Savings percentage is not supported when savings estimation mode preference is set to "
        "before discounts."
    )
    assert raw == expected_sentinel, f"expected the documented not-supported sentinel, got {raw!r}"


# ===== helpers =====
def _error_code_and_message(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS rejects must not be reported as a plain
    code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
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


def _restore_preferences(coh, original: dict) -> None:
    kwargs = {}
    if "savingsEstimationMode" in original:
        kwargs["savingsEstimationMode"] = original["savingsEstimationMode"]
    if "memberAccountDiscountVisibility" in original:
        kwargs["memberAccountDiscountVisibility"] = original["memberAccountDiscountVisibility"]
    if original.get("preferredCommitment"):
        kwargs["preferredCommitment"] = original["preferredCommitment"]
    if kwargs:
        coh.update_preferences(**kwargs)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
