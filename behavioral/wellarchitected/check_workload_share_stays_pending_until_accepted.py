"""workload-share-stays-pending-until-accepted."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "workload-share-stays-pending-until-accepted"
GROUP = 'sharing'
SERVICES = ['wellarchitected']

# A share needs a principal that is NOT this account, and no other account may be touched by a
# check. `111122223333` is AWS's documentation example account id: it is not a real AWS
# account, so the invitation this raises can never be accepted by anybody and the share is pinned
# in PENDING for as long as the check needs it. Nothing about it is specific to the calling account.
_PLACEHOLDER_PRINCIPAL = "111122223333"


# ===== helpers =====
def _delete_if_present(fn):
    """Teardown delete that tolerates the resource being gone already: the check body deletes it
    itself as part of the claim."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _poll(fn, want, what, timeout=60.0, interval=1.5):
    """Poll fn() until want(value) holds, then return that value."""
    deadline = time.time() + timeout
    while True:
        value = fn()
        if want(value):
            return value
        if time.time() >= deadline:
            raise AssertionError(f"{what}: never held within {timeout}s; last observed {value!r}")
        time.sleep(interval)


def _all_shares(wa, wid):
    """ListWorkloadShares has no botocore paginator, so loop the NextToken rather than reading
    page one."""
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


def _invitations_for(wa, workload_name):
    """ListShareInvitations, narrowed server-side to THIS check's workload name and then looped.

    The narrowing is the point: an account-wide invitation listing is a snapshot of whatever else
    is running in the account, while an empty result for a name only this run can occupy is a
    property of the query.
    """
    out, token = [], None
    while True:
        kw = {"WorkloadNamePrefix": workload_name, "ShareResourceType": "WORKLOAD"}
        if token:
            kw["NextToken"] = token
        page = wa.list_share_invitations(**kw)
        out.extend(page["ShareInvitationSummaries"])
        token = page.get("NextToken")
        if not token:
            return out


@tags(
    "axis:happy-path",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "cap:c1",
)
def run(ctx) -> None:
    """A workload share is created PENDING and stays PENDING through an UpdateWorkloadShare, the
    sharer's own ListShareInvitations does not contain it, and DeleteWorkloadShare removes it from
    the workload's share list.
    """
    wa = ctx.client("wellarchitected")
    workload_name = ctx.unique_name("sim2real-behav-wa-share-")
    wid = wa.create_workload(
        WorkloadName=workload_name,
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

    assert _all_shares(wa, wid) == [], (
        "a newly created workload already carries shares; the check's later assertions about its "
        "own share list would be meaningless"
    )

    share_id = wa.create_workload_share(
        WorkloadId=wid,
        SharedWith=_PLACEHOLDER_PRINCIPAL,
        PermissionType="READONLY",
        ClientRequestToken=str(uuid.uuid4()),
    )["ShareId"]
    ctx.on_cleanup(lambda: _delete_if_present(
        lambda: wa.delete_workload_share(
            WorkloadId=wid, ShareId=share_id, ClientRequestToken=str(uuid.uuid4()),
        )
    ))

    shares = _all_shares(wa, wid)
    assert [s["ShareId"] for s in shares] == [share_id], (
        f"the workload's shares are {[s['ShareId'] for s in shares]!r}, expected only {share_id!r}"
    )
    share = shares[0]
    assert share["Status"] == "PENDING", (
        f"a share nobody has accepted reads Status {share['Status']!r}, expected PENDING"
    )
    assert share["SharedWith"] == _PLACEHOLDER_PRINCIPAL, (
        f"the share names principal {share['SharedWith']!r}, expected {_PLACEHOLDER_PRINCIPAL!r}"
    )
    assert share["PermissionType"] == "READONLY", (
        f"the share was created READONLY but reads {share['PermissionType']!r}"
    )

    # The invitation belongs to the RECIPIENT. The sharer must not see one for its own workload.
    assert _invitations_for(wa, workload_name) == [], (
        f"the sharing account's own ListShareInvitations contains an invitation for "
        f"{workload_name!r}: {_invitations_for(wa, workload_name)!r}"
    )

    wa.update_workload_share(
        WorkloadId=wid, ShareId=share_id, PermissionType="CONTRIBUTOR",
    )
    repermissioned = _poll(
        lambda: [s for s in _all_shares(wa, wid) if s["ShareId"] == share_id][0],
        lambda s: s["PermissionType"] == "CONTRIBUTOR",
        "the share's PermissionType never became CONTRIBUTOR after UpdateWorkloadShare",
    )
    assert repermissioned["Status"] == "PENDING", (
        f"re-permissioning an unaccepted share advanced it to {repermissioned['Status']!r}; "
        f"only the recipient's acceptance may leave PENDING"
    )

    wa.delete_workload_share(
        WorkloadId=wid, ShareId=share_id, ClientRequestToken=str(uuid.uuid4()),
    )
    remaining = _poll(
        lambda: _all_shares(wa, wid),
        lambda ss: all(s["ShareId"] != share_id for s in ss),
        f"share {share_id!r} was still listed after DeleteWorkloadShare",
    )
    assert remaining == [], (
        f"deleting the only share left {remaining!r} behind on the workload"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
