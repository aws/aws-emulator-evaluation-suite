"""disassociate-members-not-a-member-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-members-not-a-member-rejected"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """DisassociateMembers for an account ID that was never added via CreateMembers
    is rejected rather than treated as a no-op success."""
    gd = ctx.client("guardduty")

    detector_id, owned = _get_or_create_detector(ctx, gd)
    if owned:
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    never_member_account_id = "111122223333"
    resp = gd.disassociate_members(
        DetectorId=detector_id,
        AccountIds=[never_member_account_id],
    )
    # GuardDuty does not raise a top-level exception for DisassociateMembers on
    # accounts that were never members; instead it rejects the account via the
    # per-account UnprocessedAccounts list rather than silently no-op'ing it.
    unprocessed = resp.get("UnprocessedAccounts", [])
    assert len(unprocessed) == 1, f"expected exactly one unprocessed account, got {unprocessed!r}"
    entry = unprocessed[0]
    assert entry["AccountId"] == never_member_account_id, (
        f"expected the unprocessed entry to name {never_member_account_id!r}, got {entry!r}"
    )
    result = entry.get("Result", "")
    expected_result = (
        "The request is rejected because the current account cannot disassociate the given "
        "member account ID since the latter is not yet associated to it."
    )
    assert result == expected_result, (
        f"expected rejection reason {expected_result!r}, got {result!r}"
    )

    # Effect absent: still no such member on record.
    members = gd.list_members(DetectorId=detector_id, OnlyAssociated="false").get("Members", [])
    assert all(m["AccountId"] != never_member_account_id for m in members), (
        f"expected no member record for {never_member_account_id}, found one in {members!r}"
    )

    # Positive control: a syntactically valid-but-unknown account ID is soft-rejected
    # via UnprocessedAccounts (a 200), while a structurally malformed one is rejected
    # outright with a top-level exception -- proving the target actually validates
    # input shape rather than uniformly stuffing every AccountIds entry into
    # UnprocessedAccounts regardless of validity.
    malformed_account_id = "abcdefghijkl"
    err = _error(
        lambda: gd.disassociate_members(DetectorId=detector_id, AccountIds=[malformed_account_id])
    )
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err!r}"
    expected = (
        "The request failed because parameter accountIds has accountId values that are "
        "formatted incorrectly."
    )
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"


def _get_or_create_detector(ctx, gd):
    """Adopt an existing detector rather than fail -- GuardDuty allows only one
    detector per account per region, so a fresh create against an account that
    already has one raises BadRequestException unrelated to this check's subject."""
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0], False
    tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    detector_id = gd.create_detector(Enable=True, Tags=tags)["DetectorId"]
    return detector_id, True


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
