"""duplicate-milestone-name-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-milestone-name-rejected"
GROUP = 'milestones'
SERVICES = ['wellarchitected']


def _error(fn, what):
    """Return the (code, message) fn() raised. A call that SUCCEEDS is the failure, so this never
    returns a falsy sentinel for it."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"{what}: the call succeeded, but real AWS rejects it")


def _milestones(wa, wid):
    """ListMilestones has no botocore paginator; loop the NextToken."""
    out, token = [], None
    while True:
        page = (
            wa.list_milestones(WorkloadId=wid, NextToken=token)
            if token else wa.list_milestones(WorkloadId=wid)
        )
        out.extend(page["MilestoneSummaries"])
        token = page.get("NextToken")
        if not token:
            return out


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """CreateMilestone refuses a name an existing milestone holds, also upper-cased or space-padded, with
    the exact conflict message; rejected calls record nothing and consume no number, so the next
    accepted name is milestone 2.
    """
    wa = ctx.client("wellarchitected")
    wid = wa.create_workload(
        WorkloadName=ctx.unique_name("sim2real-behav-wa-dupms-"),
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
    assert _milestones(wa, wid) == [], (
        f"a newly created workload already carries milestones: {_milestones(wa, wid)!r}"
    )

    name = ctx.unique_name("sim2real-behav-ms-")
    first = wa.create_milestone(
        WorkloadId=wid, MilestoneName=name, ClientRequestToken=str(uuid.uuid4()),
    )["MilestoneNumber"]
    assert first == 1, f"the first milestone was numbered {first!r}, expected 1"

    # The same name again, with a fresh idempotency token so this is a genuine second request.
    exact = _error(
        lambda: wa.create_milestone(
            WorkloadId=wid, MilestoneName=name, ClientRequestToken=str(uuid.uuid4()),
        ),
        f"re-using milestone name {name!r} within the same workload",
    )
    expected_exact = (
        "ConflictException",
        f"[Conflict] Milestone with name {name}"
        f" already exists under workload {wid}. Capitalization and whitespace are ignored in "
        "milestone names.",
    )
    assert exact == expected_exact, (
        f"a duplicate milestone name failed with {exact!r}, expected {expected_exact!r}"
    )

    upper = _error(
        lambda: wa.create_milestone(
            WorkloadId=wid, MilestoneName=name.upper(), ClientRequestToken=str(uuid.uuid4()),
        ),
        f"re-using milestone name {name!r} in a different case",
    )
    expected_upper = (
        "ConflictException",
        f"[Conflict] Milestone with name {name.upper()}"
        f" already exists under workload {wid}. Capitalization and whitespace are ignored in "
        "milestone names.",
    )
    assert upper == expected_upper, (
        f"an upper-cased duplicate milestone name failed with {upper!r}, expected "
        f"{expected_upper!r} — the name comparison is case-insensitive"
    )

    padded = _error(
        lambda: wa.create_milestone(
            WorkloadId=wid, MilestoneName=f"  {name}  ", ClientRequestToken=str(uuid.uuid4()),
        ),
        f"re-using milestone name {name!r} with surrounding whitespace",
    )
    expected_padded = (
        "ConflictException",
        f"[Conflict] Milestone with name   {name}  "
        f" already exists under workload {wid}. Capitalization and whitespace are ignored in "
        "milestone names.",
    )
    assert padded == expected_padded, (
        f"a whitespace-padded duplicate milestone name failed with {padded!r}, expected "
        f"{expected_padded!r} — the name is trimmed before comparison"
    )

    after_rejections = _milestones(wa, wid)
    assert [m["MilestoneName"] for m in after_rejections] == [name], (
        f"the three rejected CreateMilestone calls left milestones behind: "
        f"{[m['MilestoneName'] for m in after_rejections]!r}, expected only [{name!r}]"
    )

    # Positive control: the same operation accepts a name the workload does not hold, and the
    # number it receives proves the rejected attempts consumed nothing.
    other = ctx.unique_name("sim2real-behav-ms2-")
    second = wa.create_milestone(
        WorkloadId=wid, MilestoneName=other, ClientRequestToken=str(uuid.uuid4()),
    )["MilestoneNumber"]
    assert second == 2, (
        f"the second accepted milestone was numbered {second!r}, expected 2 — the rejected "
        f"attempts must not consume a milestone number"
    )
    assert sorted(m["MilestoneName"] for m in _milestones(wa, wid)) == sorted([name, other]), (
        f"the workload's milestones are "
        f"{sorted(m['MilestoneName'] for m in _milestones(wa, wid))!r}, expected exactly the two "
        f"accepted names"
    )

    # A number that was never minted is not found, though 1 and 2 are.
    missing = _error(
        lambda: wa.get_milestone(WorkloadId=wid, MilestoneNumber=second + 1),
        f"reading milestone number {second + 1} of a workload that has {second}",
    )
    expected_missing = (
        "ResourceNotFoundException",
        f"[ResourceNotFound] No milestone with number {second + 1} in a workload with ID {wid} "
        f"was found in account {ctx.account}.",
    )
    assert missing == expected_missing, (
        f"reading a milestone number that was never minted failed with {missing!r}, expected "
        f"{expected_missing!r}"
    )
    assert wa.get_milestone(
        WorkloadId=wid, MilestoneNumber=first,
    )["Milestone"]["MilestoneName"] == name, (
        "milestone 1 does not read back under the name it was created with"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
