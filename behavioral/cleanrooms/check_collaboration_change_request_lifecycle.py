"""collaboration-change-request-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "collaboration-change-request-lifecycle"
GROUP = "state-machine"
SERVICES = ["cleanrooms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CollaborationChangeRequest walks PENDING -> APPROVED -> COMMITTED, and
    committing an ADD_MEMBER change actually adds the invited account to the
    collaboration's member list."""
    cr = ctx.client("cleanrooms")

    collab_id = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
        tags={"sim2real:managed": "true"},
    )["collaboration"]["id"]
    ctx.on_cleanup(lambda: cr.delete_collaboration(collaborationIdentifier=collab_id))

    membership_id = cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED",
        tags={"sim2real:managed": "true"},
    )["membership"]["id"]
    ctx.on_cleanup(lambda: cr.delete_membership(membershipIdentifier=membership_id))

    invited_account = "111122223333"
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
    initial_status = change_request["status"]
    # The sole existing member is the creator who submitted the request, so on
    # some accounts required approvals -- and even the commit -- are already
    # satisfied at creation time.
    assert initial_status in ("PENDING", "APPROVED", "COMMITTED"), initial_status

    if initial_status == "PENDING":
        approved = cr.update_collaboration_change_request(
            collaborationIdentifier=collab_id, changeRequestIdentifier=change_id, action="APPROVE"
        )["collaborationChangeRequest"]
        assert approved["status"] == "APPROVED", approved["status"]
        initial_status = "APPROVED"

    if initial_status == "APPROVED":
        committed = cr.update_collaboration_change_request(
            collaborationIdentifier=collab_id, changeRequestIdentifier=change_id, action="COMMIT"
        )["collaborationChangeRequest"]
        assert committed["status"] == "COMMITTED", committed["status"]
    else:
        committed = cr.get_collaboration_change_request(
            collaborationIdentifier=collab_id, changeRequestIdentifier=change_id
        )["collaborationChangeRequest"]
        assert committed["status"] == "COMMITTED", committed["status"]
    ctx.on_cleanup(lambda: cr.delete_member(collaborationIdentifier=collab_id, accountId=invited_account))

    members = cr.list_members(collaborationIdentifier=collab_id)["memberSummaries"]
    added = [m for m in members if m["accountId"] == invited_account]
    assert len(added) == 1, added
    assert added[0]["status"] == "INVITED", added[0]["status"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
