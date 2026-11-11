"""put-permission-revision-id-changes-on-update."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "put-permission-revision-id-changes-on-update"
GROUP = "policy"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second PutPermission call (with the correct current revisionId) replaces
    the principal set for the actionGroup and issues a new, different revisionId."""
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-cgp-permrev-")
    token = str(uuid.uuid4())
    cgp.create_profiling_group(
        profilingGroupName=name, clientToken=token, tags={"sim2real-audit": "true"}
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    account_id = sts.get_caller_identity()["Account"]
    principal_1 = f"arn:aws:iam::{account_id}:root"
    # A real, currently-existing IAM principal (the caller's own ARN) so the
    # service's principal-existence validation accepts it.
    principal_2 = sts.get_caller_identity()["Arn"]

    first = cgp.put_permission(
        profilingGroupName=name, actionGroup="agentPermissions", principals=[principal_1]
    )
    rev1 = first["revisionId"]

    second = cgp.put_permission(
        profilingGroupName=name,
        actionGroup="agentPermissions",
        principals=[principal_1, principal_2],
        revisionId=rev1,
    )
    rev2 = second["revisionId"]
    assert rev2 != rev1, f"expected a new revisionId after update, got the same one back: {rev1!r}"

    policy_doc = json.loads(second["policy"])
    blob = json.dumps(policy_doc)
    assert principal_1 in blob and principal_2 in blob, (
        f"expected both {principal_1!r} and {principal_2!r} in the updated policy, got {blob}"
    )

    fetched = cgp.get_policy(profilingGroupName=name)
    assert fetched["revisionId"] == rev2, (
        f"expected an independent GetPolicy to report revisionId {rev2!r}, got {fetched['revisionId']!r}"
    )
    fetched_blob = json.dumps(json.loads(fetched["policy"]))
    assert principal_1 in fetched_blob and principal_2 in fetched_blob, (
        f"expected both {principal_1!r} and {principal_2!r} in the policy read back from GetPolicy, "
        f"got {fetched_blob}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
