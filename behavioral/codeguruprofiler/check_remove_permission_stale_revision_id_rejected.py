"""remove-permission-stale-revision-id-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-permission-stale-revision-id-rejected"
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
    """RemovePermission with a stale (superseded) revisionId is rejected with
    ConflictException, leaves the current policy untouched, and removing with the
    correct current revisionId succeeds."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-stale-")
    token = str(uuid.uuid4())
    cgp.create_profiling_group(
        profilingGroupName=name, clientToken=token, tags={"env": "sim2real"}
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    # The account root exists in every account; a second PutPermission with the
    # same principal still advances the revisionId.
    principal_1 = f"arn:aws:iam::{ctx.account}:root"

    put1 = cgp.put_permission(
        profilingGroupName=name, actionGroup="agentPermissions", principals=[principal_1]
    )
    stale_rev = put1["revisionId"]
    # Advance the policy so stale_rev is no longer current.
    put2 = cgp.put_permission(
        profilingGroupName=name,
        actionGroup="agentPermissions",
        principals=[principal_1],
        revisionId=stale_rev,
    )
    current_rev = put2["revisionId"]
    assert current_rev != stale_rev, (current_rev, stale_rev)

    err = _error(
        lambda: cgp.remove_permission(
            profilingGroupName=name, actionGroup="agentPermissions", revisionId=stale_rev
        )
    )
    assert err["Code"] == "ConflictException", err
    expected = f"Policy has been updated since the revision: {stale_rev}, new RevisionId: {current_rev}"
    assert err["Message"] == expected, (err["Message"], expected)

    # effect absent: policy is still the current one, unaffected
    still_there = cgp.get_policy(profilingGroupName=name)
    assert still_there["revisionId"] == current_rev, still_there
    assert still_there["policy"] == put2["policy"], still_there["policy"]

    # positive control: remove with the correct, current revisionId succeeds.
    # This removes the last/only actionGroup, so the whole policy is deleted:
    # a subsequent GetPolicy succeeds but reports no policy/revisionId at all
    # (the "policy-less" state), rather than raising an error.
    cgp.remove_permission(
        profilingGroupName=name, actionGroup="agentPermissions", revisionId=current_rev
    )
    after = cgp.get_policy(profilingGroupName=name)
    assert "policy" not in after, after
    assert "revisionId" not in after, after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
