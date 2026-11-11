"""collaboration-change-request-reapprove-rejected."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "collaboration-change-request-reapprove-rejected"
GROUP = "overly-permissive"
SERVICES = ["cleanrooms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """In a single-member collaboration with no auto-approved change types, the creator's change request is
    COMMITTED and auto-approved at creation; approving it again fails with ValidationException and the exact
    COMMITTED-status message, and it stays COMMITTED."""
    cr = ctx.client("cleanrooms")

    collab_id = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
        autoApprovedChangeRequestTypes=[],
    )["collaboration"]["id"]
    membership_ids = []
    ctx.on_cleanup(lambda: _delete_collaboration_then_memberships(cr, collab_id, membership_ids))

    membership_id = cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED"
    )["membership"]["id"]
    membership_ids.append(membership_id)

    change_request = cr.create_collaboration_change_request(
        collaborationIdentifier=collab_id,
        changes=[{
            "specificationType": "MEMBER",
            "specification": {
                "member": {
                    "accountId": "111122223333",
                    "memberAbilities": [],
                    "displayName": "invited-member",
                }
            },
        }],
    )["collaborationChangeRequest"]
    change_id = change_request["id"]
    status_before = change_request["status"]
    # Even with autoApprovedChangeRequestTypes=[], a
    # single-member collaboration's own change request reaches COMMITTED
    # (never PENDING or merely APPROVED) at creation, and the API says so.
    assert status_before == "COMMITTED", status_before
    assert change_request["isAutoApproved"] is True, change_request["isAutoApproved"]

    error = _error(lambda: cr.update_collaboration_change_request(
        collaborationIdentifier=collab_id, changeRequestIdentifier=change_id, action="APPROVE"
    ))
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == (
        f"You can't update change request {change_id} because it's in COMMITTED status. "
        "Change requests in COMMITTED or CANCELLED status can't be modified."
    ), error

    still = cr.get_collaboration_change_request(
        collaborationIdentifier=collab_id, changeRequestIdentifier=change_id
    )["collaborationChangeRequest"]
    assert still["status"] == "COMMITTED", still["status"]


def _delete_collaboration_then_memberships(cr, collab_id, membership_ids):
    """The creator's ACTIVE membership cannot be deleted, so the collaboration goes first and
    each membership is deleted once it reads COLLABORATION_DELETED."""
    cr.delete_collaboration(collaborationIdentifier=collab_id)
    for membership_id in membership_ids:
        deadline = time.monotonic() + 60
        status = None
        while time.monotonic() < deadline:
            status = cr.get_membership(membershipIdentifier=membership_id)["membership"]["status"]
            if status == "COLLABORATION_DELETED":
                break
            time.sleep(2)
        else:
            raise AssertionError(f"membership {membership_id} never reached COLLABORATION_DELETED: {status}")
        cr.delete_membership(membershipIdentifier=membership_id)


def _error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS
    raises, so an emulator accepting what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
