"""start-monitoring-member-non-member-not-found-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-monitoring-member-non-member-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["detective"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """StartMonitoringMember fails with ResourceNotFoundException for a never-added account ("No such membership")
    and for an invited member that never reached ACCEPTED_BUT_DISABLED ("invitation has not been accepted"),
    and neither call creates or advances a member record."""
    d = ctx.client("detective")
    arn = d.create_graph()["GraphArn"]
    # An account administers at most one behavior graph per Region; CreateGraph returns that
    # graph, so it is left in place.

    never_added_account = _fake_account_id(ctx)

    code, message = _error(lambda: d.start_monitoring_member(GraphArn=arn, AccountId=never_added_account))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "No such membership", f"unexpected message: {message!r}"

    members = d.get_members(GraphArn=arn, AccountIds=[never_added_account])
    assert members["MemberDetails"] == [], f"expected no member record, got {members!r}"
    assert never_added_account in [
        u["AccountId"] for u in members.get("UnprocessedAccounts", [])
    ], f"expected {never_added_account!r} to be unprocessed, got {members!r}"

    # A member that DOES have a real member record, but never reached ACCEPTED_BUT_DISABLED, is a
    # different broken precondition: a fabricated account/email pair deterministically fails
    # verification and is never a valid StartMonitoringMember source state. AWS answers the SAME
    # ResourceNotFoundException here as for a true non-member, even while the member is still
    # mid-verification; it is not a ConflictException.
    unverifiable_account = _fake_account_id(ctx)
    email = f"sim2real-detective-{uuid.uuid4().hex[:10]}@example.com"
    d.create_members(
        GraphArn=arn,
        Accounts=[{"AccountId": unverifiable_account, "EmailAddress": email}],
        DisableEmailNotification=True,
    )
    ctx.on_cleanup(lambda: _delete_members_quietly(d, arn, [unverifiable_account]))

    status_before = _get_member_status(d, arn, unverifiable_account)
    assert status_before in ("INVITED", "VERIFICATION_IN_PROGRESS", "VERIFICATION_FAILED"), (
        f"expected the fabricated invite to be pending or failed verification, got status {status_before!r}"
    )

    code2, message2 = _error(lambda: d.start_monitoring_member(GraphArn=arn, AccountId=unverifiable_account))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2!r}"
    assert message2 == "invitation has not been accepted", f"unexpected message: {message2!r}"

    status_after = _get_member_status(d, arn, unverifiable_account)
    assert status_after in ("INVITED", "VERIFICATION_IN_PROGRESS", "VERIFICATION_FAILED"), (
        f"a rejected StartMonitoringMember must not advance the member to an eligible "
        f"state, was {status_before!r}, now {status_after!r}"
    )

    # Positive control: other member operations on the same graph remain usable throughout,
    # and the still-unverified member is visible (not silently dropped) via ListMembers.
    listed = d.list_members(GraphArn=arn).get("MemberDetails", [])
    assert any(m["AccountId"] == unverifiable_account for m in listed), (
        f"expected {unverifiable_account!r} to be visible via ListMembers, got {listed!r}"
    )


def _fake_account_id(ctx) -> str:
    import random

    real_account = ctx.client("sts").get_caller_identity()["Account"]
    while True:
        candidate = "9" + "".join(str(random.randint(0, 9)) for _ in range(11))
        if candidate != real_account:
            return candidate


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _get_member_status(d, graph_arn: str, account_id: str) -> str:
    resp = d.get_members(GraphArn=graph_arn, AccountIds=[account_id])
    details = resp.get("MemberDetails", [])
    assert len(details) == 1, f"expected exactly one member detail, got {details!r}"
    return details[0]["Status"]


def _delete_members_quietly(d, graph_arn: str, account_ids: list[str]) -> None:
    from botocore.exceptions import ClientError

    try:
        d.delete_members(GraphArn=graph_arn, AccountIds=account_ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
