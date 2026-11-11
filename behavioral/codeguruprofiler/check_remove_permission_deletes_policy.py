"""remove-permission-deletes-policy."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-permission-deletes-policy"
GROUP = "policy"
SERVICES = ["codeguruprofiler"]


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemovePermission on the (only) agentPermissions actionGroup removes the whole
    policy, so a subsequent GetPolicy succeeds but reports no policy/revisionId
    (the "policy-less" state), not the stale contents."""
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-cgp-permrm-")
    token = str(uuid.uuid4())
    cgp.create_profiling_group(profilingGroupName=name, clientToken=token)
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    account_id = sts.get_caller_identity()["Account"]
    principal = f"arn:aws:iam::{account_id}:root"
    put = cgp.put_permission(
        profilingGroupName=name, actionGroup="agentPermissions", principals=[principal]
    )
    rev1 = put["revisionId"]

    # Positive control: the policy is actually readable, with the principal we
    # just granted, before we remove it -- rules out a target whose GetPolicy
    # always reports the policy-less state regardless of what was put.
    before = cgp.get_policy(profilingGroupName=name)
    assert before["revisionId"] == rev1, before
    assert principal in before["policy"], before

    removed = cgp.remove_permission(
        profilingGroupName=name, actionGroup="agentPermissions", revisionId=rev1
    )
    # Removing the only actionGroup deletes the whole resource policy: the
    # response's policy document no longer contains any Statement for the
    # principal that was granted, confirming the removal actually took effect
    # (rather than just echoing back the pre-removal policy/revisionId).
    assert principal not in removed.get("policy", ""), removed

    after = cgp.get_policy(profilingGroupName=name)
    assert "policy" not in after, after
    assert "revisionId" not in after, after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
