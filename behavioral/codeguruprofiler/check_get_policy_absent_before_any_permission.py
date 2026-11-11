"""get-policy-absent-before-any-permission."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-policy-absent-before-any-permission"
GROUP = "policy"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPolicy on a new profiling group succeeds without policy or revisionId fields, and after PutPermission
    the same call returns a policy and the revisionId PutPermission returned.
    """
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-cgp-")

    cgp.create_profiling_group(profilingGroupName=name, clientToken=str(uuid.uuid4()))
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    response = cgp.get_policy(profilingGroupName=name)
    assert "policy" not in response, response
    assert "revisionId" not in response, response

    principal = f"arn:aws:iam::{sts.get_caller_identity()['Account']}:root"
    put_resp = cgp.put_permission(
        profilingGroupName=name, actionGroup="agentPermissions", principals=[principal]
    )
    assert put_resp.get("revisionId"), put_resp

    after = cgp.get_policy(profilingGroupName=name)
    assert "policy" in after, after
    assert after.get("revisionId") == put_resp["revisionId"], after


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
