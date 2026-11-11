"""member-association-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "member-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["guardduty"]
_DOC_ACCOUNT = "444455556666"  # an AWS documentation account id: it names no real account


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """A created member starts in RelationshipStatus "Created"; DisassociateMembers on a
    never-invited member leaves its record unchanged rather than fabricating "Removed", while
    DeleteMembers erases the record so GetMembers returns nothing for the account."""
    gd = ctx.client("guardduty")
    detector_id = _get_or_create_detector(ctx)
    member_id = _DOC_ACCOUNT

    if gd.get_members(DetectorId=detector_id, AccountIds=[member_id])["Members"]:
        gd.delete_members(DetectorId=detector_id, AccountIds=[member_id])  # an interrupted run left it

    create_resp = gd.create_members(
        DetectorId=detector_id,
        AccountDetails=[{"AccountId": member_id, "Email": "sim2real-behav@example.com"}],
    )
    unprocessed_on_create = create_resp.get("UnprocessedAccounts", [])
    assert unprocessed_on_create == [], (
        f"expected CreateMembers to accept {member_id} outright, "
        f"got UnprocessedAccounts={unprocessed_on_create!r}"
    )
    ctx.on_cleanup(lambda: _safe_delete_member(ctx, detector_id, member_id))

    created = gd.get_members(DetectorId=detector_id, AccountIds=[member_id])
    assert len(created["Members"]) == 1, f"expected exactly 1 member record, got {created['Members']!r}"
    created_status = created["Members"][0]["RelationshipStatus"]
    assert created_status == "Created", f"expected RelationshipStatus 'Created' right after CreateMembers, got {created_status!r}"

    gd.disassociate_members(DetectorId=detector_id, AccountIds=[member_id])

    still_created = gd.get_members(DetectorId=detector_id, AccountIds=[member_id])
    assert len(still_created["Members"]) == 1, (
        f"expected the member record to still exist after disassociating a Created-only "
        f"member, got {still_created['Members']!r}"
    )
    still_created_status = still_created["Members"][0]["RelationshipStatus"]
    assert still_created_status == "Created", (
        f"a member that never reached Enabled/Disabled must not transition on "
        f"DisassociateMembers -- expected RelationshipStatus to stay 'Created', "
        f"got {still_created_status!r}"
    )

    delete_resp = gd.delete_members(DetectorId=detector_id, AccountIds=[member_id])
    unprocessed_on_delete = delete_resp.get("UnprocessedAccounts", [])
    assert unprocessed_on_delete == [], (
        f"expected DeleteMembers to unconditionally erase {member_id} regardless of "
        f"relationship status, got UnprocessedAccounts={unprocessed_on_delete!r}"
    )

    after_delete = gd.get_members(DetectorId=detector_id, AccountIds=[member_id])
    assert after_delete["Members"] == [], (
        f"expected no member record for {member_id} after DeleteMembers, "
        f"got {after_delete['Members']!r}"
    )
    dead_entry = next(
        (u for u in after_delete["UnprocessedAccounts"] if u["AccountId"] == member_id), None
    )
    assert dead_entry is not None, (
        f"expected GetMembers to report {member_id} as unprocessed (no such member) "
        f"after DeleteMembers, got UnprocessedAccounts={after_delete['UnprocessedAccounts']!r}"
    )
    assert dead_entry.get("Result"), f"expected a non-empty rejection reason for the deleted member, got {dead_entry!r}"


# ===== helpers =====

def _get_or_create_detector(ctx) -> str:
    gd = ctx.client("guardduty")
    ids = gd.list_detectors().get("DetectorIds", [])
    if ids:
        return ids[0]
    detector_id = gd.create_detector(
        Enable=True, Tags={"sim2real-check": "member-association-lifecycle"}
    )["DetectorId"]

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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
