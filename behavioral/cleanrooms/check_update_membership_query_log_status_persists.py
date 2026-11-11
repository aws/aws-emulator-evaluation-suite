"""update-membership-query-log-status-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-membership-query-log-status-persists"
GROUP = "state"
SERVICES = ["cleanrooms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMembership's queryLogStatus change is durably persisted -- a fresh
    GetMembership call (not just the update response) reflects the new value and
    a bumped updateTime."""
    cr = ctx.client("cleanrooms")

    collab_id = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="ENABLED",
        tags={"purpose": "behavioral-check"},
    )["collaboration"]["id"]
    ctx.on_cleanup(lambda: cr.delete_collaboration(collaborationIdentifier=collab_id))

    membership = cr.create_membership(
        collaborationIdentifier=collab_id,
        queryLogStatus="DISABLED",
        tags={"purpose": "behavioral-check"},
    )["membership"]
    membership_id = membership["id"]
    ctx.on_cleanup(lambda: cr.delete_membership(membershipIdentifier=membership_id))

    assert membership["queryLogStatus"] == "DISABLED", (
        f"expected freshly created membership to start DISABLED, got {membership['queryLogStatus']!r}"
    )
    original_update_time = membership["updateTime"]

    cr.update_membership(membershipIdentifier=membership_id, queryLogStatus="ENABLED")

    fetched = cr.get_membership(membershipIdentifier=membership_id)["membership"]
    assert fetched["queryLogStatus"] == "ENABLED", (
        f"expected a fresh GetMembership to reflect ENABLED after UpdateMembership, got {fetched['queryLogStatus']!r}"
    )
    assert fetched["updateTime"] > original_update_time, (
        f"expected updateTime to advance past {original_update_time!r} after UpdateMembership, got {fetched['updateTime']!r}"
    )

    # Toggle back and confirm the second update also persists (not a one-shot echo).
    second_update_time = fetched["updateTime"]
    cr.update_membership(membershipIdentifier=membership_id, queryLogStatus="DISABLED")
    fetched_again = cr.get_membership(membershipIdentifier=membership_id)["membership"]
    assert fetched_again["queryLogStatus"] == "DISABLED", (
        f"expected the second UpdateMembership to flip queryLogStatus back to DISABLED, got {fetched_again['queryLogStatus']!r}"
    )
    assert fetched_again["updateTime"] > second_update_time, (
        f"expected updateTime to advance again past {second_update_time!r} on the second UpdateMembership, got {fetched_again['updateTime']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
