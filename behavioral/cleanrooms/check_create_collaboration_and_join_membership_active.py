"""create-collaboration-and-join-membership-active."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-collaboration-and-join-membership-active"
GROUP = "state"
SERVICES = ["cleanrooms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Creating a collaboration does not itself grant the creator a membership --
    the creator must call CreateMembership to join, after which GetMembership and
    GetCollaboration both reflect an ACTIVE, fully-abled member."""
    cr = ctx.client("cleanrooms")

    collab = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="ENABLED",
        tags={"env": "sim2real", "purpose": "behavioral-check"},
    )["collaboration"]
    collab_id = collab["id"]
    ctx.on_cleanup(lambda: cr.delete_collaboration(collaborationIdentifier=collab_id))

    # Creation alone does not join the creator: right after
    # CreateCollaboration the creator's own memberStatus is INVITED, with no
    # membershipId/membershipArn present at all, until CreateMembership is called.
    assert collab["memberStatus"] == "INVITED", (
        f"expected the creator to be INVITED (not yet joined) immediately after "
        f"CreateCollaboration, got {collab['memberStatus']!r}"
    )
    assert "membershipId" not in collab, (
        f"expected no membershipId before CreateMembership, got {collab.get('membershipId')!r}"
    )

    membership = cr.create_membership(
        collaborationIdentifier=collab_id,
        queryLogStatus="ENABLED",
        tags={"env": "sim2real", "purpose": "behavioral-check"},
    )["membership"]
    membership_id = membership["id"]
    ctx.on_cleanup(lambda: cr.delete_membership(membershipIdentifier=membership_id))

    assert membership["status"] == "ACTIVE", (
        f"expected a freshly created membership to be ACTIVE, got {membership['status']!r}"
    )
    assert membership["collaborationId"] == collab_id, (
        f"expected membership.collaborationId == {collab_id!r}, got {membership['collaborationId']!r}"
    )
    assert sorted(membership["memberAbilities"]) == ["CAN_QUERY", "CAN_RECEIVE_RESULTS"], (
        f"expected memberAbilities ['CAN_QUERY', 'CAN_RECEIVE_RESULTS'], "
        f"got {sorted(membership['memberAbilities'])!r}"
    )

    fetched = cr.get_membership(membershipIdentifier=membership_id)["membership"]
    assert fetched["status"] == "ACTIVE", (
        f"expected an independent GetMembership read to see ACTIVE, got {fetched['status']!r}"
    )

    seen = cr.get_collaboration(collaborationIdentifier=collab_id)["collaboration"]
    assert seen["memberStatus"] == "ACTIVE", (
        f"expected GetCollaboration to reflect the creator's memberStatus as ACTIVE, "
        f"got {seen['memberStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
