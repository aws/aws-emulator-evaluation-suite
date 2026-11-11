"""start-protected-query-bad-membership-not-found."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-protected-query-bad-membership-not-found"
GROUP = "error-semantics"
SERVICES = ["cleanrooms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartProtectedQuery against a membership identifier that does not exist is
    rejected with ResourceNotFoundException; a real membership created in the same
    file remains fully usable (positive control)."""
    cr = ctx.client("cleanrooms")

    bogus_membership_id = str(uuid.uuid4())
    error = _error(lambda: cr.start_protected_query(
        type="SQL",
        membershipIdentifier=bogus_membership_id,
        sqlParameters={"queryString": "SELECT 1"},
    ))
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent membership, got {error!r}"
    )
    assert error["Message"] == (
        f"No such membership: {bogus_membership_id} for account {ctx.account}"
    ), error

    # Positive control: a real membership is unaffected and still describable.
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
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED", tags={"sim2real": CHECK}
    )["membership"]["id"]
    membership_ids.append(membership_id)

    real = cr.get_membership(membershipIdentifier=membership_id)["membership"]
    assert real["status"] == "ACTIVE", f"expected ACTIVE status, got {real['status']!r}"
    assert real["id"] == membership_id, (
        f"expected membership id {membership_id!r}, got {real['id']!r}"
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
