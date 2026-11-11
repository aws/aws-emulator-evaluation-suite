"""remove-permission-stale-revision-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-permission-stale-revision-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemovePermission with a stale revisionId fails with ConflictException and its exact message and leaves the
    policy unchanged, while the current revisionId removes it, so GetPolicy carries no policy or revisionId.
    """
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"env": "sim2real"},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    # The account root exists in every account; a second PutPermission with the
    # same principal still advances the revisionId.
    p1 = f"arn:aws:iam::{ctx.account}:root"

    rev1 = cgp.put_permission(
        profilingGroupName=name, actionGroup="agentPermissions", principals=[p1]
    )["revisionId"]
    put2 = cgp.put_permission(
        profilingGroupName=name,
        actionGroup="agentPermissions",
        principals=[p1],
        revisionId=rev1,
    )
    rev2 = put2["revisionId"]
    assert rev2 != rev1, f"revisionId did not advance on update: {rev2!r} == {rev1!r}"

    # Break exactly one thing: attempt removal with the stale rev1.
    err = _error(
        lambda: cgp.remove_permission(
            profilingGroupName=name, actionGroup="agentPermissions", revisionId=rev1
        )
    )
    assert err["Code"] == "ConflictException", (
        f"expected ConflictException for stale revisionId, got {err['Code']!r}"
    )
    expected = f"Policy has been updated since the revision: {rev1}, new RevisionId: {rev2}"
    assert err["Message"] == expected, (err["Message"], expected)

    # Effect absent: the policy at rev2 is still present, unremoved.
    got = cgp.get_policy(profilingGroupName=name)
    assert got["revisionId"] == rev2, f"expected revisionId {rev2!r} unchanged, got {got.get('revisionId')!r}"
    assert got["policy"] == put2["policy"], f"expected policy {put2['policy']!r} unchanged, got {got['policy']!r}"

    # Positive control: removal with the correct current revisionId succeeds.
    cgp.remove_permission(
        profilingGroupName=name, actionGroup="agentPermissions", revisionId=rev2
    )
    after = cgp.get_policy(profilingGroupName=name)
    assert "policy" not in after, after
    assert "revisionId" not in after, after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
