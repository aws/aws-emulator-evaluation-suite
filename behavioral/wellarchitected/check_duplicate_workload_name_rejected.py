"""duplicate-workload-name-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-workload-name-rejected"
GROUP = 'workloads'
SERVICES = ['wellarchitected']


# ===== helpers =====
def _delete_if_present(fn):
    """Teardown delete that tolerates the resource being gone already: the check body deletes it
    itself as part of the claim."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _client_error(fn, what):
    """Return the (code, message) fn() raised. A call that SUCCEEDS is the failure, so this never
    returns a falsy sentinel for it."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"{what}: the call succeeded, but real AWS rejects it")


def _workloads_named(wa, prefix):
    """ListWorkloads narrowed server-side to a name this run minted, then looped over NextToken.

    The narrowing is the point: the account may hold other workloads, so an account-wide
    listing would be a snapshot of the neighbours rather than a property of this check.
    """
    out, token = [], None
    while True:
        kw = {"WorkloadNamePrefix": prefix, "MaxResults": 50}
        if token:
            kw["NextToken"] = token
        page = wa.list_workloads(**kw)
        out.extend(page["WorkloadSummaries"])
        token = page.get("NextToken")
        if not token:
            return out


def _create(ctx, wa, name, token=None):
    return wa.create_workload(
        WorkloadName=name,
        Description="sim2real behavioral check workload",
        Environment="PREPRODUCTION",
        ReviewOwner="sim2real@example.com",
        Lenses=["wellarchitected"],
        AwsRegions=[ctx.region],
        ClientRequestToken=token or str(uuid.uuid4()),
        Tags={"sim2real": CHECK},
    )


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """A workload name is unique per account: re-sending CreateWorkload with the same token returns
    the same WorkloadId, a fresh token conflicts and creates nothing, and one workload remains.
    """
    wa = ctx.client("wellarchitected")
    name = ctx.unique_name("sim2real-behav-wa-dup-")
    assert _workloads_named(wa, name) == [], (
        f"the freshly minted workload name {name!r} is already taken in this account"
    )

    token = str(uuid.uuid4())
    created = _create(ctx, wa, name, token)
    wid = created["WorkloadId"]
    ctx.on_cleanup(
        lambda: wa.delete_workload(WorkloadId=wid, ClientRequestToken=str(uuid.uuid4()))
    )

    # The same request, re-sent verbatim: an idempotent retry, not a duplicate.
    retried = _create(ctx, wa, name, token)
    assert retried["WorkloadId"] == wid, (
        f"re-sending the create with the same ClientRequestToken returned WorkloadId "
        f"{retried['WorkloadId']!r}, expected the original {wid!r}"
    )

    # The same name under a new token is a genuine second create, and conflicts.
    code, message = _client_error(
        lambda: _create(ctx, wa, name),
        f"creating a second workload named {name!r}",
    )
    assert code == "ConflictException", (
        f"a duplicate workload name failed with {code!r}, expected ConflictException"
    )
    expected = f"[Conflict] A workload with name {name} already exists."
    assert message == expected, (
        f"a duplicate workload name was refused with message {message!r}, expected {expected!r}"
    )
    named = _workloads_named(wa, name)
    assert [w["WorkloadId"] for w in named] == [wid], (
        f"the name {name!r} is held by {[w['WorkloadId'] for w in named]!r}, expected only the one "
        f"accepted workload"
    )

    # Positive control: the same operation accepts a name the account does not hold.
    other_name = ctx.unique_name("sim2real-behav-wa-dup2-")
    other_wid = _create(ctx, wa, other_name)["WorkloadId"]
    ctx.on_cleanup(lambda: _delete_if_present(
        lambda: wa.delete_workload(WorkloadId=other_wid, ClientRequestToken=str(uuid.uuid4()))
    ))
    assert other_wid != wid, (
        f"a workload created under a different name reused WorkloadId {wid!r}"
    )
    assert [w["WorkloadId"] for w in _workloads_named(wa, other_name)] == [other_wid], (
        f"the second name {other_name!r} is held by "
        f"{[w['WorkloadId'] for w in _workloads_named(wa, other_name)]!r}"
    )

    # Deleting one name frees it; the other workload is untouched.
    wa.delete_workload(WorkloadId=other_wid, ClientRequestToken=str(uuid.uuid4()))
    assert _workloads_named(wa, other_name) == [], (
        f"the deleted workload is still listed under {other_name!r}: "
        f"{_workloads_named(wa, other_name)!r}"
    )
    missing, missing_message = _client_error(
        lambda: wa.get_workload(WorkloadId=other_wid),
        "reading a workload that was deleted",
    )
    assert missing == "ResourceNotFoundException", (
        f"reading a deleted workload failed with {missing!r}, expected ResourceNotFoundException"
    )
    expected = (
        f"[ResourceNotFound] No workload with ID {other_wid} was found in account {ctx.account}."
    )
    assert missing_message == expected, (
        f"reading a deleted workload was refused with message {missing_message!r}, expected "
        f"{expected!r}"
    )
    assert wa.get_workload(WorkloadId=wid)["Workload"]["WorkloadName"] == name, (
        "deleting the other workload disturbed the one that holds the contested name"
    )
    reused = _create(ctx, wa, other_name)["WorkloadId"]
    ctx.on_cleanup(
        lambda: wa.delete_workload(WorkloadId=reused, ClientRequestToken=str(uuid.uuid4()))
    )
    assert reused != other_wid, (
        f"re-creating a deleted workload's name returned the deleted id {other_wid!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
