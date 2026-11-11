"""preferences-partial-update-preserves-unspecified-fields."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "preferences-partial-update-preserves-unspecified-fields"
GROUP = "state"
SERVICES = ["cost-optimization-hub"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment", "resource:account-singleton:cost-optimization-hub-preferences")
def run(ctx) -> None:
    """UpdatePreferences merges into existing preferences rather than resetting omitted fields."""
    # Cost Optimization Hub's control plane exists only in us-east-1, regardless of ctx.region.
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    # GetPreferences/UpdatePreferences reject an unenrolled account. A never-enrolled
    # account reports no item at all rather than an explicit "Inactive" one. Enroll
    # idempotently and restore whatever enrollment status was there before.
    existing = coh.list_enrollment_statuses()["items"]
    original_enrollment = existing[0]["status"] if existing else "Inactive"
    ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_enrollment))
    if original_enrollment != "Active":
        coh.update_enrollment_status(status="Active")
        _poll_until(
            lambda: coh.list_enrollment_statuses()["items"][0]["status"],
            lambda status: status == "Active",
            timeout_s=30.0,
        )

    original = coh.get_preferences()
    ctx.on_cleanup(lambda: _restore(coh, original))

    # Establish a known baseline covering both fields this account can set.
    # (savingsEstimationMode="AfterDiscounts" and memberAccountDiscountVisibility are excluded: real
    # AWS rejects both here with a management-account-only restriction, so BeforeDiscounts is the
    # only reachable mode.)
    baseline = coh.update_preferences(
        savingsEstimationMode="BeforeDiscounts",
        preferredCommitment={"term": "OneYear", "paymentOption": "PartialUpfront"},
    )
    assert baseline["savingsEstimationMode"] == "BeforeDiscounts", (
        f"expected baseline savingsEstimationMode=BeforeDiscounts, got {baseline['savingsEstimationMode']!r}"
    )
    assert baseline["preferredCommitment"]["term"] == "OneYear", (
        f"expected baseline preferredCommitment.term=OneYear, got {baseline['preferredCommitment']['term']!r}"
    )

    # Now update ONLY preferredCommitment; savingsEstimationMode must be left untouched.
    partial = coh.update_preferences(
        preferredCommitment={"term": "ThreeYears", "paymentOption": "NoUpfront"}
    )
    assert partial["preferredCommitment"]["term"] == "ThreeYears", (
        f"expected partial preferredCommitment.term=ThreeYears, got {partial['preferredCommitment']['term']!r}"
    )
    assert partial["preferredCommitment"]["paymentOption"] == "NoUpfront", (
        f"expected partial preferredCommitment.paymentOption=NoUpfront, got {partial['preferredCommitment']['paymentOption']!r}"
    )
    assert partial["savingsEstimationMode"] == "BeforeDiscounts", (
        f"partial update reset savingsEstimationMode, got {partial['savingsEstimationMode']!r}"
    )

    fetched = coh.get_preferences()
    assert fetched["preferredCommitment"]["term"] == "ThreeYears", (
        f"fetched preferredCommitment.term diverged from update response, got {fetched['preferredCommitment']['term']!r}"
    )
    assert fetched["preferredCommitment"]["paymentOption"] == "NoUpfront", (
        f"fetched preferredCommitment.paymentOption diverged from update response, "
        f"got {fetched['preferredCommitment']['paymentOption']!r}"
    )
    assert fetched["savingsEstimationMode"] == "BeforeDiscounts", (
        f"fetched savingsEstimationMode diverged from update response, got {fetched['savingsEstimationMode']!r}"
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


def _restore(coh, original: dict) -> None:
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
