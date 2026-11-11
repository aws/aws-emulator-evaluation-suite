"""put-permission-then-get-policy-matches."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-permission-then-get-policy-matches"
GROUP = "permissions"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPermission's returned policy/revisionId exactly match what GetPolicy
    subsequently returns, and the policy document grants the specific
    agentPermissions actions to the exact principal named in the request."""
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"env": "test", "owner": "sim2real"},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    principal_arn = f"arn:aws:iam::{account_id}:root"

    put_resp = cgp.put_permission(
        profilingGroupName=name,
        actionGroup="agentPermissions",
        principals=[principal_arn],
    )
    ctx.on_cleanup(
        lambda: cgp.remove_permission(
            profilingGroupName=name,
            actionGroup="agentPermissions",
            revisionId=cgp.get_policy(profilingGroupName=name)["revisionId"],
        )
    )

    policy_doc = json.loads(put_resp["policy"])
    statement = policy_doc["Statement"][0]
    assert statement["Principal"]["AWS"] == principal_arn, statement["Principal"]
    actions = statement["Action"]
    actions = actions if isinstance(actions, list) else [actions]
    assert "codeguru-profiler:ConfigureAgent" in actions, actions
    assert "codeguru-profiler:PostAgentProfile" in actions, actions

    got = cgp.get_policy(profilingGroupName=name)
    assert got["policy"] == put_resp["policy"], (got["policy"], put_resp["policy"])
    assert got["revisionId"] == put_resp["revisionId"], (
        got["revisionId"],
        put_resp["revisionId"],
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
