"""put-permission-creates-policy-with-revision-id."""
from __future__ import annotations

import json
import re
import uuid

from behavioral_harness import tags

CHECK = "put-permission-creates-policy-with-revision-id"
GROUP = "policy"
SERVICES = ["codeguruprofiler"]

_UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPermission creates a resource policy statement for the given principal
    and returns a UUID revisionId that GetPolicy subsequently reflects."""
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-cgp-perm-")
    token = str(uuid.uuid4())
    cgp.create_profiling_group(profilingGroupName=name, clientToken=token)
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    account_id = sts.get_caller_identity()["Account"]
    principal = f"arn:aws:iam::{account_id}:root"

    put = cgp.put_permission(
        profilingGroupName=name,
        actionGroup="agentPermissions",
        principals=[principal],
    )
    assert _UUID_RE.match(put["revisionId"]), (
        f"expected PutPermission revisionId to be a UUID, got {put['revisionId']!r}"
    )
    policy_doc = json.loads(put["policy"])
    statements = policy_doc["Statement"]
    assert any(principal in json.dumps(s.get("Principal", {})) for s in statements), (
        f"expected principal {principal!r} in policy statements, got {statements!r}"
    )

    fetched = cgp.get_policy(profilingGroupName=name)
    assert fetched["revisionId"] == put["revisionId"], (
        f"expected GetPolicy revisionId {put['revisionId']!r}, got {fetched['revisionId']!r}"
    )
    assert json.loads(fetched["policy"]) == policy_doc, (
        f"expected GetPolicy policy to match PutPermission policy {policy_doc!r}, "
        f"got {json.loads(fetched['policy'])!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
