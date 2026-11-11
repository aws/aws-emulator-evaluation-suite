"""delete-collaboration-cascades-membership-status."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-collaboration-cascades-membership-status"
GROUP = "state"
SERVICES = ["cleanrooms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteCollaboration, GetCollaboration and CreateMembership on it fail with
    AccessDeniedException and the exact message, while the creator's membership stays readable and
    reaches status COLLABORATION_DELETED within 60 s."""
    cr = ctx.client("cleanrooms")

    collab = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
    )["collaboration"]
    collab_id = collab["id"]
    collab_arn = collab["arn"]
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    membership_id = cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED"
    )["membership"]["id"]
    ctx.on_cleanup(lambda: cr.delete_membership(membershipIdentifier=membership_id))

    cr.delete_collaboration(collaborationIdentifier=collab_id)

    error = _error(lambda: cr.get_collaboration(collaborationIdentifier=collab_id))
    assert error["Code"] == "AccessDeniedException", (
        f"expected AccessDeniedException reading a deleted collaboration, got {error!r}"
    )
    assert error["Message"] == (
        f"User: {caller_arn} is not authorized to perform: cleanrooms:GetCollaboration "
        f"on resource: {collab_arn}"
    ), error

    error = _error(lambda: cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED"
    ))
    assert error["Code"] == "AccessDeniedException", (
        f"expected CreateMembership against a deleted collaboration to fail with "
        f"AccessDeniedException, got {error!r}"
    )
    assert error["Message"] == (
        f"User: {caller_arn} is not authorized to perform: cleanrooms:CreateMembership on resource: *"
    ), error

    final = _poll_membership_status(ctx, cr, membership_id, "COLLABORATION_DELETED", timeout_s=60)
    assert final["status"] == "COLLABORATION_DELETED", (
        f"expected membership status COLLABORATION_DELETED after collaboration delete, "
        f"got {final['status']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS
    raises, so an emulator accepting what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_membership_status(ctx, cr, membership_id, expected, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cr.get_membership(membershipIdentifier=membership_id)["membership"]
        if last["status"] == expected:
            return last
        time.sleep(2)
    raise AssertionError(f"membership never reached {expected!r}, last saw {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
