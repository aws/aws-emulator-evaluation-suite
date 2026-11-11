"""create-membership-duplicate-conflict."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-membership-duplicate-conflict"
GROUP = "error-semantics"
SERVICES = ["cleanrooms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second CreateMembership in the same collaboration fails with ValidationException and the exact INVITED-state
    message and leaves the original membership ACTIVE; the creator's DeleteMembership on it fails with ConflictException
    and the exact message."""
    cr = ctx.client("cleanrooms")
    resource_tags = {"sim2real": "behavioral-check"}

    collab_id = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
        tags=resource_tags,
    )["collaboration"]["id"]
    membership_ids = []
    ctx.on_cleanup(lambda: _delete_collaboration_then_memberships(cr, collab_id, membership_ids))

    membership_id = cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED", tags=resource_tags
    )["membership"]["id"]
    membership_ids.append(membership_id)

    error = _error(lambda: cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED"
    ))
    assert error["Code"] == "ValidationException", f"expected ValidationException for duplicate membership, got {error!r}"
    assert error["Message"] == (
        f"Cannot create membership for account: {ctx.account}. "
        "Memberships can only be created for members in INVITED state"
    ), error

    still = cr.get_membership(membershipIdentifier=membership_id)["membership"]
    assert still["status"] == "ACTIVE", (
        f"expected original membership ACTIVE after rejected duplicate, got {still['status']!r}"
    )
    assert still["id"] == membership_id, (
        f"expected original membership id {membership_id!r} unchanged, got {still['id']!r}"
    )

    # Positive control: the collaboration itself is still fully usable.
    seen = cr.get_collaboration(collaborationIdentifier=collab_id)["collaboration"]
    assert seen["id"] == collab_id, f"expected collaboration {collab_id!r} still reachable, got {seen['id']!r}"

    # The duplicate rejection isn't something the creator can work around by
    # leaving and rejoining: DeleteMembership on their own ACTIVE membership is
    # itself rejected, so this pair has no restore path.
    delete_error = _error(lambda: cr.delete_membership(membershipIdentifier=membership_id))
    assert delete_error["Code"] == "ConflictException", (
        f"expected ConflictException deleting the creator's own ACTIVE membership, got {delete_error!r}"
    )
    assert delete_error["Message"] == (
        "Cannot delete membership for the creator of the collaboration while their membership is still ACTIVE."
    ), delete_error
    still2 = cr.get_membership(membershipIdentifier=membership_id)["membership"]
    assert still2["status"] == "ACTIVE", (
        f"expected membership still ACTIVE after rejected self-delete, got {still2['status']!r}"
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
