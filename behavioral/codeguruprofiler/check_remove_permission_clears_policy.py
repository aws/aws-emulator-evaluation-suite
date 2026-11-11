"""remove-permission-clears-policy."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-permission-clears-policy"
GROUP = "policy"
SERVICES = ["codeguruprofiler"]


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemovePermission deletes the agentPermissions policy statement; afterwards GetPolicy
    succeeds (the group still exists) but carries no `policy`/`revisionId` fields, because
    no resource policy exists any more."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")
    principal = f"arn:aws:iam::{ctx.account}:root"

    cgp.create_profiling_group(profilingGroupName=name, clientToken=str(uuid.uuid4()))
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    put_resp = cgp.put_permission(
        profilingGroupName=name, actionGroup="agentPermissions", principals=[principal]
    )
    revision_id = put_resp["revisionId"]

    # sanity: the policy is readable right after it is written
    read_back = cgp.get_policy(profilingGroupName=name)["revisionId"]
    assert read_back == revision_id, (revision_id, read_back)

    cgp.remove_permission(
        profilingGroupName=name, actionGroup="agentPermissions", revisionId=revision_id
    )

    after = cgp.get_policy(profilingGroupName=name)
    assert "policy" not in after, after
    assert "revisionId" not in after, after

    # the identifier is now dead: a further mutation against the consumed revisionId
    # is rejected rather than silently no-op'ing on a policy that no longer exists.
    err = _error(
        lambda: cgp.remove_permission(
            profilingGroupName=name, actionGroup="agentPermissions", revisionId=revision_id
        )
    )
    assert err["Code"] == "ResourceNotFoundException", err
    expected = f"No policy attached to profiling group name: {name} in accountId: {ctx.account}; "
    assert err["Message"] == expected, (err["Message"], expected)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
