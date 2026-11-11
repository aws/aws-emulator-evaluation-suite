"""create-members-malformed-account-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-members-malformed-account-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateMembers with a malformed (non-12-digit) AWS account ID is rejected with
    BadRequestException instead of being accepted and silently dropped."""
    gd = ctx.client("guardduty")

    detector_id = gd.create_detector(
        Enable=True, Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    )["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    # 12 characters (passes client-side length validation) but not a valid numeric
    # AWS account ID.
    malformed_account_id = "abcdefghijkl"
    code, message = _error_code(
        lambda: gd.create_members(
            DetectorId=detector_id,
            AccountDetails=[{"AccountId": malformed_account_id, "Email": "sim2real-malformed@example.com"}],
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected_message = "The request failed because the 'accountId' was formatted incorrectly."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the malformed account never shows up as a member.
    members = gd.list_members(DetectorId=detector_id, OnlyAssociated="false").get("Members", [])
    assert all(m["AccountId"] != malformed_account_id for m in members), (
        f"malformed account {malformed_account_id!r} was rejected but still appears as a member: {members}"
    )

    # Positive control: a syntactically valid (12-digit numeric) account ID is
    # accepted and recorded as a member, even though the account does not really
    # exist -- CreateMembers only validates format here, not membership/reality.
    valid_format_account_id = "111122223333"
    resp = gd.create_members(
        DetectorId=detector_id,
        AccountDetails=[{"AccountId": valid_format_account_id, "Email": "sim2real-valid@example.com"}],
    )
    ctx.on_cleanup(lambda: gd.delete_members(DetectorId=detector_id, AccountIds=[valid_format_account_id]))
    assert resp.get("UnprocessedAccounts", []) == [], (
        f"expected the valid-format account to be processed, got UnprocessedAccounts={resp.get('UnprocessedAccounts')!r}"
    )

    members_after = gd.list_members(DetectorId=detector_id, OnlyAssociated="false").get("Members", [])
    assert any(m["AccountId"] == valid_format_account_id for m in members_after), (
        f"expected {valid_format_account_id!r} to appear as a member, got {members_after}"
    )


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected BadRequestException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
