"""put-permission-invalid-action-group-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-permission-invalid-action-group-rejected"
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
    """PutPermission only supports actionGroup="agentPermissions"; any other value is rejected
    with ValidationException and no policy is written, while the supported value still
    succeeds (positive control)."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")
    principal = f"arn:aws:iam::{ctx.account}:root"

    cgp.create_profiling_group(profilingGroupName=name, clientToken=str(uuid.uuid4()))
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    err = _error(
        lambda: cgp.put_permission(
            profilingGroupName=name, actionGroup="bogusPermissions", principals=[principal]
        )
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
    expected = (
        "1 validation error detected: Value 'bogusPermissions' at 'actionGroup' failed to "
        "satisfy constraint: Member must satisfy enum value set: "
        "[internalAgentPermissions, agentPermissions]"
    )
    assert err["Message"] == expected, (err["Message"], expected)

    # effect absent: still no policy at all for this profiling group (GetPolicy
    # succeeds on a policy-less-but-existing group, carrying no policy/revisionId)
    no_policy_response = cgp.get_policy(profilingGroupName=name)
    assert "policy" not in no_policy_response, no_policy_response
    assert "revisionId" not in no_policy_response, no_policy_response

    # positive control: the only supported actionGroup value succeeds
    put_resp = cgp.put_permission(
        profilingGroupName=name, actionGroup="agentPermissions", principals=[principal]
    )
    assert put_resp["revisionId"], f"expected a revisionId on successful PutPermission, got {put_resp}"
    get_resp = cgp.get_policy(profilingGroupName=name)
    assert get_resp["revisionId"] == put_resp["revisionId"], (
        f"expected GetPolicy revisionId {put_resp['revisionId']!r} to match PutPermission's, "
        f"got {get_resp['revisionId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
