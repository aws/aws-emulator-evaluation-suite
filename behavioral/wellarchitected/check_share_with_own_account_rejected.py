"""share-with-own-account-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "share-with-own-account-rejected"
GROUP = 'sharing'
SERVICES = ['wellarchitected']

# A share needs a principal that is NOT the sharer. `111122223333` is AWS's documentation example
# account id: not a real AWS account, so the positive control below touches nobody and
# its invitation can never be accepted. Nothing here is specific to the calling account — the
# rejected principal is read from STS at runtime.
_PLACEHOLDER_PRINCIPAL = "111122223333"


# ===== helpers =====
def _client_error(fn, what):
    """Return the (code, message) fn() raised. A call that SUCCEEDS is the failure, so this never
    returns a falsy sentinel for it."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"{what}: the call succeeded, but real AWS rejects it")


def _all_shares(wa, wid):
    """ListWorkloadShares has no botocore paginator; loop the NextToken."""
    out, token = [], None
    while True:
        page = (
            wa.list_workload_shares(WorkloadId=wid, NextToken=token)
            if token else wa.list_workload_shares(WorkloadId=wid)
        )
        out.extend(page["WorkloadShareSummaries"])
        token = page.get("NextToken")
        if not token:
            return out


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """Sharing a workload with the caller's own account is rejected and leaves no share behind,
    while the same request shape is accepted for a different principal.
    """
    wa = ctx.client("wellarchitected")
    own_account = ctx.client("sts").get_caller_identity()["Account"]

    wid = wa.create_workload(
        WorkloadName=ctx.unique_name("sim2real-behav-wa-self-"),
        Description="sim2real behavioral check workload",
        Environment="PREPRODUCTION",
        ReviewOwner="sim2real@example.com",
        Lenses=["wellarchitected"],
        AwsRegions=[ctx.region],
        ClientRequestToken=str(uuid.uuid4()),
        Tags={"sim2real": CHECK},
    )["WorkloadId"]
    ctx.on_cleanup(
        lambda: wa.delete_workload(WorkloadId=wid, ClientRequestToken=str(uuid.uuid4()))
    )

    code, message = _client_error(
        lambda: wa.create_workload_share(
            WorkloadId=wid,
            SharedWith=own_account,
            PermissionType="READONLY",
            ClientRequestToken=str(uuid.uuid4()),
        ),
        "sharing a workload with its own owning account",
    )
    assert code == "ValidationException", (
        f"sharing with the sharer's own principal failed with {code!r}, expected ValidationException"
    )
    expected = (
        "[Validation] The shared with principal cannot be the same as the sharer's principal."
    )
    assert message == expected, (
        f"sharing with the sharer's own principal was refused with message {message!r}, expected "
        f"{expected!r}"
    )
    assert _all_shares(wa, wid) == [], (
        f"the rejected self-share left a share on the workload: {_all_shares(wa, wid)!r}"
    )

    # Positive control: the same request shape, differing only in the principal, is accepted.
    share_id = wa.create_workload_share(
        WorkloadId=wid,
        SharedWith=_PLACEHOLDER_PRINCIPAL,
        PermissionType="READONLY",
        ClientRequestToken=str(uuid.uuid4()),
    )["ShareId"]
    ctx.on_cleanup(lambda: wa.delete_workload_share(
        WorkloadId=wid, ShareId=share_id, ClientRequestToken=str(uuid.uuid4()),
    ))
    shares = _all_shares(wa, wid)
    assert [s["ShareId"] for s in shares] == [share_id], (
        f"the accepted share is not the workload's only share: "
        f"{[s['ShareId'] for s in shares]!r}"
    )
    assert shares[0]["SharedWith"] == _PLACEHOLDER_PRINCIPAL, (
        f"the accepted share names principal {shares[0]['SharedWith']!r}, expected "
        f"{_PLACEHOLDER_PRINCIPAL!r}"
    )

    # A malformed PermissionType is refused by the same operation that just succeeded.
    bad_permission, bad_permission_message = _client_error(
        lambda: wa.create_workload_share(
            WorkloadId=wid,
            SharedWith=_PLACEHOLDER_PRINCIPAL,
            PermissionType="READONLY_EXTRA",
            ClientRequestToken=str(uuid.uuid4()),
        ),
        "sharing a workload with an unknown PermissionType",
    )
    assert bad_permission == "ValidationException", (
        f"an unknown PermissionType failed with {bad_permission!r}, expected ValidationException"
    )
    expected = (
        '[Validation] [instance value ("READONLY_EXTRA") not found in enum '
        '(possible values: ["READONLY","CONTRIBUTOR"])]'
    )
    assert bad_permission_message == expected, (
        f"an unknown PermissionType was refused with message {bad_permission_message!r}, expected "
        f"{expected!r}"
    )
    assert [s["ShareId"] for s in _all_shares(wa, wid)] == [share_id], (
        f"the rejected PermissionType left an extra share: {_all_shares(wa, wid)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
