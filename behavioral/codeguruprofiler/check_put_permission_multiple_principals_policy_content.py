"""put-permission-multiple-principals-policy-content."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "put-permission-multiple-principals-policy-content"
GROUP = "policy"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPermission with two principals writes a statement whose Principal list holds exactly both ARNs, and
    GetPolicy returns that statement at the same revisionId.
    """
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-cgp-")
    account_id = sts.get_caller_identity()["Account"]
    principal_a = f"arn:aws:iam::{account_id}:root"
    # A real, currently-existing IAM principal (the caller's own ARN) so the
    # service's principal-existence validation accepts it.
    principal_b = sts.get_caller_identity()["Arn"]

    cgp.create_profiling_group(
        profilingGroupName=name, clientToken=str(uuid.uuid4()), tags={"env": "sim2real"}
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    put_resp = cgp.put_permission(
        profilingGroupName=name,
        actionGroup="agentPermissions",
        principals=[principal_a, principal_b],
    )

    get_resp = cgp.get_policy(profilingGroupName=name)
    assert get_resp["revisionId"] == put_resp["revisionId"], (
        f"expected GetPolicy revisionId {put_resp['revisionId']!r}, "
        f"got {get_resp['revisionId']!r}"
    )
    policy_doc = json.loads(get_resp["policy"])
    statement = policy_doc["Statement"][0]
    principal_field = statement["Principal"]["AWS"]
    principal_list = principal_field if isinstance(principal_field, list) else [principal_field]
    assert principal_a in principal_list, f"expected {principal_a} in {principal_list}"
    assert principal_b in principal_list, f"expected {principal_b} in {principal_list}"
    assert len(principal_list) == 2, f"expected exactly 2 principals, got {principal_list}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
