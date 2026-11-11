"""create-members-invalid-account-id-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-members-invalid-account-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]
_DOC_ACCOUNTS = ("111122223333", "444455556666")  # AWS documentation account ids: they name no real account


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateMembers with a 12-digit AccountId but a malformed Email is rejected server-side
    with BadRequestException and creates no member, while a well-formed account/email pair
    in the same detector still succeeds (positive control)."""
    gd = ctx.client("guardduty")
    detector_id = _get_or_create_detector(ctx)
    bad_pair_account_id = _DOC_ACCOUNTS[0]

    if gd.get_members(DetectorId=detector_id, AccountIds=[_DOC_ACCOUNTS[1]])["Members"]:
        gd.delete_members(DetectorId=detector_id, AccountIds=[_DOC_ACCOUNTS[1]])  # an interrupted run left it
    before = gd.list_members(DetectorId=detector_id)["Members"]
    before_count = len(before)

    code, message = _error_code(
        lambda: gd.create_members(
            DetectorId=detector_id,
            AccountDetails=[{"AccountId": bad_pair_account_id, "Email": "not-a-valid-email"}],
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException for malformed Email, got {code!r}"
    expected_message = "The request failed because provided `emailId` was formatted incorrectly."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_reject = gd.list_members(DetectorId=detector_id)["Members"]
    assert len(after_reject) == before_count, (
        f"expected member count unchanged after rejected CreateMembers, "
        f"before={before_count} after={len(after_reject)}"
    )

    good_id = _DOC_ACCOUNTS[1]
    create_resp = gd.create_members(
        DetectorId=detector_id,
        AccountDetails=[{"AccountId": good_id, "Email": "sim2real-behav@example.com"}],
    )
    assert create_resp["UnprocessedAccounts"] == [], (
        f"expected positive control CreateMembers to fully succeed, "
        f"got UnprocessedAccounts={create_resp['UnprocessedAccounts']!r}"
    )
    ctx.on_cleanup(lambda: _safe_delete_member(ctx, detector_id, good_id))

    member = gd.get_members(DetectorId=detector_id, AccountIds=[good_id])["Members"][0]
    assert member["RelationshipStatus"] == "Created", (
        f"expected RelationshipStatus 'Created' for newly invited member, got {member['RelationshipStatus']!r}"
    )


# ===== helpers =====

def _get_or_create_detector(ctx) -> str:
    gd = ctx.client("guardduty")
    ids = gd.list_detectors().get("DetectorIds", [])
    if ids:
        return ids[0]
    detector_id = gd.create_detector(Enable=True)["DetectorId"]

    def _cleanup():
        try:
            gd.delete_detector(DetectorId=detector_id)
        except ClientError as err:
            # GuardDuty reports a detector that is already gone as BadRequestException.
            if err.response["Error"]["Code"] != "BadRequestException":
                raise

    ctx.on_cleanup(_cleanup)
    return detector_id


def _safe_delete_member(ctx, detector_id: str, member_id: str) -> None:
    gd = ctx.client("guardduty")
    # GuardDuty reports a member or detector that is already gone as BadRequestException.
    for op in (gd.disassociate_members, gd.delete_members):
        try:
            op(DetectorId=detector_id, AccountIds=[member_id])
        except ClientError as err:
            if err.response["Error"]["Code"] != "BadRequestException":
                raise


def _error_code(fn) -> Any:
    """Call fn(); return its error code and message. An unexpected SUCCESS raises: a target that
    accepts a pair real AWS refuses must not be reduced to a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected BadRequestException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
