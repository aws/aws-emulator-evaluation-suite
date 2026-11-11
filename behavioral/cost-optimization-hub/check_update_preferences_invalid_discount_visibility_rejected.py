"""update-preferences-invalid-discount-visibility-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-preferences-invalid-discount-visibility-rejected"
GROUP = "overly-permissive"
SERVICES = ["cost-optimization-hub"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment", "resource:account-singleton:cost-optimization-hub-preferences")
def run(ctx) -> None:
    """UpdatePreferences rejects an out-of-enum memberAccountDiscountVisibility with generic input
    validation and an in-enum one from a member account with a management-account-only error,
    neither changes GetPreferences, and a preferredCommitment update succeeds as control."""
    # cost-optimization-hub does not exist in us-west-2 (NXDOMAIN there); pinned to us-east-1
    # through ctx.client(..., region=) so the check's own credentials are still wired in and
    # an emulator run still reaches the emulator's shared endpoint.
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    # Preferences are only reachable once the account is enrolled: real AWS answers GetPreferences
    # with AccessDeniedException("AWS account is not enrolled for recommendations") otherwise, and
    # a never-enrolled account has no ListEnrollmentStatuses item at all. Create-or-adopt the
    # enrollment prerequisite and restore it after.
    statuses = coh.list_enrollment_statuses().get("items", [])
    enrollment_status = statuses[0]["status"] if statuses else "Inactive"
    if enrollment_status != "Active":
        coh.update_enrollment_status(status="Active")
        ctx.on_cleanup(lambda: coh.update_enrollment_status(status=enrollment_status))

    original = coh.get_preferences()
    ctx.on_cleanup(lambda: _restore(coh, original))

    # Positive control: a field with no member/management restriction updates cleanly and
    # persists, proving the account is enrolled and otherwise healthy for Preferences.
    target_commitment = {"term": "OneYear", "paymentOption": "PartialUpfront"}
    control = coh.update_preferences(preferredCommitment=target_commitment)
    assert control["preferredCommitment"] == target_commitment, (
        f"positive control: expected preferredCommitment {target_commitment!r}, got "
        f'{control.get("preferredCommitment")!r}'
    )
    confirmed = coh.get_preferences()
    assert confirmed["preferredCommitment"] == target_commitment, (
        f"the positive control did not persist: expected {target_commitment!r}, got "
        f'{confirmed.get("preferredCommitment")!r}'
    )

    # An out-of-enum value fails generic input validation.
    invalid_response = _error(
        lambda: coh.update_preferences(memberAccountDiscountVisibility="Everyone")
    )
    invalid_error = invalid_response["Error"]
    assert invalid_error["Code"] == "ValidationException", (
        f'expected "ValidationException" for an out-of-enum memberAccountDiscountVisibility, '
        f'got {invalid_error["Code"]!r}'
    )
    expected_invalid = "Input validation failed. Please check the field list for more details."
    assert invalid_error["Message"] == expected_invalid, (
        f"expected {expected_invalid!r}, got {invalid_error['Message']!r}"
    )
    expected_fields = [
        {
            "fieldName": "memberAccountDiscountVisibility",
            "message": "Member must satisfy enum value set: [All, None]",
        }
    ]
    assert invalid_response.get("fields") == expected_fields, (
        f"expected fields {expected_fields!r}, got {invalid_response.get('fields')!r}"
    )

    # A WITHIN-enum value is rejected too, but for a different, specific reason: this account is
    # a member account, and only an organization's management account may set this field.
    restricted_error = _error(lambda: coh.update_preferences(memberAccountDiscountVisibility="All"))[
        "Error"
    ]
    assert restricted_error["Code"] == "ValidationException", (
        f'expected "ValidationException" for memberAccountDiscountVisibility from a member '
        f'account, got {restricted_error["Code"]!r}'
    )
    expected_restricted = "Only management accounts can update member account discount visibility."
    assert restricted_error["Message"] == expected_restricted, (
        f"expected {expected_restricted!r}, got {restricted_error['Message']!r}"
    )
    assert restricted_error["Message"] != invalid_error["Message"], (
        "the out-of-enum rejection and the member-account rejection must be distinguishable, but "
        f"both calls returned the identical message {invalid_error['Message']!r}"
    )

    # Neither rejected call had any effect: memberAccountDiscountVisibility stays unreported for
    # a member account, exactly as it was before either attempt -- an INDEPENDENT read, not
    # either mutating call's own response.
    final = coh.get_preferences()
    assert "memberAccountDiscountVisibility" not in final, (
        f"memberAccountDiscountVisibility should stay unreported for a member account, but "
        f'GetPreferences now returns {final.get("memberAccountDiscountVisibility")!r}'
    )


# ===== helpers =====
def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _restore(coh, original: dict) -> None:
    kwargs = {}
    if "savingsEstimationMode" in original:
        kwargs["savingsEstimationMode"] = original["savingsEstimationMode"]
    if "memberAccountDiscountVisibility" in original:
        kwargs["memberAccountDiscountVisibility"] = original["memberAccountDiscountVisibility"]
    if "preferredCommitment" in original:
        kwargs["preferredCommitment"] = original["preferredCommitment"]
    if kwargs:
        coh.update_preferences(**kwargs)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
