"""delete-member-creator-rejected."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-member-creator-rejected"
GROUP = "overly-permissive"
SERVICES = ["cleanrooms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteMember on the collaboration creator fails with ConflictException and the exact message, and the
    creator stays listed with an ACTIVE membership; the same call on an invited member sets its status to
    REMOVED."""
    cr = ctx.client("cleanrooms")
    sts = ctx.client("sts")
    creator_account_id = sts.get_caller_identity()["Account"]
    invited_account = "111122223333"

    collab_id = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
        tags={"sim2real": CHECK},
    )["collaboration"]["id"]
    membership_ids = []
    ctx.on_cleanup(lambda: _delete_collaboration_then_memberships(cr, collab_id, membership_ids))

    membership_id = cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED",
        tags={"sim2real": CHECK},
    )["membership"]["id"]
    membership_ids.append(membership_id)

    # Positive control: invite a non-creator member via a change request (with a
    # single-member collaboration this is often auto-approved/committed at
    # creation, since the sole existing member -- the creator -- already
    # satisfies the approval requirement), then remove it with the identical
    # DeleteMember call under test.
    change_request = cr.create_collaboration_change_request(
        collaborationIdentifier=collab_id,
        changes=[{
            "specificationType": "MEMBER",
            "specification": {
                "member": {
                    "accountId": invited_account,
                    "memberAbilities": [],
                    "displayName": "invited-member",
                }
            },
        }],
    )["collaborationChangeRequest"]
    change_id = change_request["id"]
    status = change_request["status"]
    if status == "PENDING":
        status = cr.update_collaboration_change_request(
            collaborationIdentifier=collab_id, changeRequestIdentifier=change_id, action="APPROVE"
        )["collaborationChangeRequest"]["status"]
    if status == "APPROVED":
        cr.update_collaboration_change_request(
            collaborationIdentifier=collab_id, changeRequestIdentifier=change_id, action="COMMIT"
        )

    invited_before = cr.list_members(collaborationIdentifier=collab_id)["memberSummaries"]
    assert any(m["accountId"] == invited_account for m in invited_before), (
        f"expected {invited_account} to appear as an invited member, saw {invited_before}"
    )

    cr.delete_member(collaborationIdentifier=collab_id, accountId=invited_account)

    invited_after = cr.list_members(collaborationIdentifier=collab_id)["memberSummaries"]
    invited_entry = next((m for m in invited_after if m["accountId"] == invited_account), None)
    # DeleteMember does not drop the member from the list (mirrors how
    # DeleteCollaboration leaves membership records behind with a terminal
    # status) -- it flips MemberStatus to REMOVED in place.
    assert invited_entry is not None and invited_entry["status"] == "REMOVED", (
        f"expected {invited_account} status REMOVED after DeleteMember, saw {invited_entry}"
    )

    error = _error(lambda: cr.delete_member(
        collaborationIdentifier=collab_id, accountId=creator_account_id
    ))
    assert error["Code"] == "ConflictException", f"expected ConflictException removing the creator, got {error!r}"
    assert error["Message"] == (
        "Cannot delete member for the creator of the collaboration until the collaboration is deleted."
    ), error

    still = cr.get_membership(membershipIdentifier=membership_id)["membership"]
    assert still["status"] == "ACTIVE", (
        f"expected creator membership ACTIVE after rejected removal, got {still['status']!r}"
    )

    members = cr.list_members(collaborationIdentifier=collab_id)["memberSummaries"]
    assert any(m["accountId"] == creator_account_id for m in members), (
        f"expected creator {creator_account_id} still listed as a member, saw {members}"
    )

    # Positive control: the collaboration and its metadata are still fully
    # functional after the rejected removal attempt.
    seen = cr.get_collaboration(collaborationIdentifier=collab_id)["collaboration"]
    assert seen["creatorAccountId"] == creator_account_id, (
        f"expected creatorAccountId {creator_account_id}, got {seen['creatorAccountId']!r}"
    )


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
