"""put-permission-get-policy-roundtrip."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "put-permission-get-policy-roundtrip"
GROUP = "policy"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPermission writes a resource policy statement granting agentPermissions to the given
    principal, and GetPolicy returns that exact policy document and revisionId."""
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-cgp-")
    account_id = sts.get_caller_identity()["Account"]
    principal = f"arn:aws:iam::{account_id}:root"

    cgp.create_profiling_group(
        profilingGroupName=name, clientToken=str(uuid.uuid4()), tags={"env": "sim2real"}
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    put_resp = cgp.put_permission(
        profilingGroupName=name, actionGroup="agentPermissions", principals=[principal]
    )
    policy_doc = json.loads(put_resp["policy"])
    revision_id = put_resp["revisionId"]

    statement = policy_doc["Statement"][0]
    granted_principal = statement["Principal"]["AWS"]
    assert granted_principal == principal or principal in granted_principal, (
        f"expected principal {principal!r} in policy Principal.AWS, got {granted_principal!r}"
    )
    actions = statement["Action"]
    actions = actions if isinstance(actions, list) else [actions]
    assert "codeguru-profiler:ConfigureAgent" in actions, (
        f"expected ConfigureAgent in granted actions, got {actions!r}"
    )
    assert "codeguru-profiler:PostAgentProfile" in actions, (
        f"expected PostAgentProfile in granted actions, got {actions!r}"
    )

    get_resp = cgp.get_policy(profilingGroupName=name)
    assert get_resp["revisionId"] == revision_id, (
        f"GetPolicy revisionId {get_resp['revisionId']!r} != PutPermission revisionId {revision_id!r}"
    )
    fetched_doc = json.loads(get_resp["policy"])
    assert fetched_doc == policy_doc, (
        f"GetPolicy policy {fetched_doc!r} != PutPermission policy {policy_doc!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
