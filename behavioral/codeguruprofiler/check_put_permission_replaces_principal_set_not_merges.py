"""put-permission-replaces-principal-set-not-merges."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-permission-replaces-principal-set-not-merges"
GROUP = "policy"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second PutPermission on the same actionGroup replaces the principal set: after granting p1 and p2 and
    then only p2, the returned and the GetPolicy policy contain p2 but not p1.
    """
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-cgp-")
    # Two distinct, real, currently-existing IAM principals (account root and the
    # caller's own ARN) so the service's principal-existence validation accepts them.
    principal1 = f"arn:aws:iam::{account_id}:root"
    principal2 = sts.get_caller_identity()["Arn"]

    def _cleanup():
        try:
            policy = cgp.get_policy(profilingGroupName=name)
            if "revisionId" in policy:
                cgp.remove_permission(
                    profilingGroupName=name,
                    actionGroup="agentPermissions",
                    revisionId=policy["revisionId"],
                )
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        cgp.delete_profiling_group(profilingGroupName=name)

    cgp.create_profiling_group(profilingGroupName=name, tags={"env": "sim2real"})
    ctx.on_cleanup(_cleanup)

    put1 = cgp.put_permission(
        profilingGroupName=name,
        actionGroup="agentPermissions",
        principals=[principal1, principal2],
    )
    revision0 = put1["revisionId"]
    both_text = json.dumps(json.loads(put1["policy"]))
    assert principal1 in both_text and principal2 in both_text, (
        f"expected both {principal1!r} and {principal2!r} in initial policy, got {both_text}"
    )

    put2 = cgp.put_permission(
        profilingGroupName=name,
        actionGroup="agentPermissions",
        principals=[principal2],
        revisionId=revision0,
    )
    replaced_text = json.dumps(json.loads(put2["policy"]))
    assert principal2 in replaced_text, (
        f"expected {principal2!r} to remain in replaced policy, got {replaced_text}"
    )
    assert principal1 not in replaced_text, (
        f"expected {principal1!r} to be gone from replaced policy (replace, not merge), "
        f"got {replaced_text}"
    )

    fetched_text = json.dumps(json.loads(cgp.get_policy(profilingGroupName=name)["policy"]))
    assert principal2 in fetched_text, (
        f"expected {principal2!r} in GetPolicy's independently-read policy, got {fetched_text}"
    )
    assert principal1 not in fetched_text, (
        f"expected {principal1!r} absent from GetPolicy's independently-read policy "
        f"(replace, not merge), got {fetched_text}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
