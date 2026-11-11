"""preferences-savings-estimation-mode-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "preferences-savings-estimation-mode-roundtrip"
GROUP = "state"
SERVICES = ["cost-optimization-hub"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment", "resource:account-singleton:cost-optimization-hub-preferences")
def run(ctx) -> None:
    """UpdatePreferences(savingsEstimationMode=BeforeDiscounts) is echoed and read back by GetPreferences,
    while AfterDiscounts on a member account fails with ValidationException and its exact message and
    leaves the mode at BeforeDiscounts."""
    # cost-optimization-hub has a single API endpoint, us-east-1 only — region-pinned, not a literal.
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    # GetPreferences/UpdatePreferences 403 with AccessDeniedException on an account that has never
    # opted in — enroll (create-or-adopt) so the check works on a fresh account too, and restore
    # whatever enrollment state we found on cleanup. A never-enrolled account reports no item at
    # all, not an explicit "Inactive" one.
    enrollment_items = coh.list_enrollment_statuses().get("items", [])
    original_enrollment = enrollment_items[0]["status"] if enrollment_items else "Inactive"
    if original_enrollment != "Active":
        coh.update_enrollment_status(status="Active")
        ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_enrollment))

    original = coh.get_preferences()
    ctx.on_cleanup(lambda: _restore(coh, original))

    # Positive control: BeforeDiscounts needs no elevated permission, so this proves the account
    # and credentials are otherwise healthy for UpdatePreferences before the negative below.
    update_resp = coh.update_preferences(savingsEstimationMode="BeforeDiscounts")
    assert update_resp["savingsEstimationMode"] == "BeforeDiscounts", (
        f"UpdatePreferences echo: expected savingsEstimationMode='BeforeDiscounts', "
        f"got {update_resp.get('savingsEstimationMode')!r}"
    )
    fetched = coh.get_preferences()
    assert fetched["savingsEstimationMode"] == "BeforeDiscounts", (
        f"GetPreferences after update: expected savingsEstimationMode='BeforeDiscounts', "
        f"got {fetched.get('savingsEstimationMode')!r}"
    )

    # Negative: AfterDiscounts is refused deterministically on a non-management account because
    # memberAccountDiscountVisibility is not (and, on this account, cannot be) enabled.
    error = _client_error(lambda: coh.update_preferences(savingsEstimationMode="AfterDiscounts"))
    assert error.get("Code") == "ValidationException", (
        f"AfterDiscounts on a member account: expected ValidationException, got {error!r}"
    )
    message = error.get("Message", "")
    expected_message = (
        "Invalid permission to update preferences. To use AfterDiscounts savings estimation mode, "
        "the management account must either enable member account discount visibility in Cost "
        "Optimization Hub, or enable linked account discount visibility in Cost Management "
        "Preferences."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    unchanged = coh.get_preferences()
    assert unchanged["savingsEstimationMode"] == "BeforeDiscounts", (
        f"savingsEstimationMode must be unchanged after the rejected AfterDiscounts attempt, "
        f"got {unchanged.get('savingsEstimationMode')!r}"
    )


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
