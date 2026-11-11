"""get-membership-not-found."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-membership-not-found"
GROUP = "error-semantics"
SERVICES = ["cleanrooms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMembership on a nonexistent membership id fails with ResourceNotFoundException "No such membership:
    <id> for account <account>", while GetMembership and ListMemberships return a real membership."""
    cr = ctx.client("cleanrooms")

    bogus_id = str(uuid.uuid4())
    error = _error(lambda: cr.get_membership(membershipIdentifier=bogus_id))
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a bogus membership id, got {error!r}"
    )
    assert error["Message"] == f"No such membership: {bogus_id} for account {ctx.account}", error

    collab_id = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
    )["collaboration"]["id"]
    membership_ids = []
    ctx.on_cleanup(lambda: _delete_collaboration_then_memberships(cr, collab_id, membership_ids))

    membership_id = cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED"
    )["membership"]["id"]
    membership_ids.append(membership_id)

    fetched = cr.get_membership(membershipIdentifier=membership_id)["membership"]
    assert fetched["id"] == membership_id, (
        f"expected GetMembership({membership_id!r}) to return that id, got {fetched.get('id')!r}"
    )

    memberships = cr.list_memberships()["membershipSummaries"]
    assert any(m["id"] == membership_id for m in memberships), (
        f"expected {membership_id!r} among ListMemberships results, "
        f"got {[m['id'] for m in memberships]!r}"
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
