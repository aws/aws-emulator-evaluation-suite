"""delete-resource-policy-rejects-stale-policy-hash."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-rejects-stale-policy-hash"
GROUP = "state-machine"
SERVICES = ["ssm"]


def _delete_policy_if_present(ssm, resource_arn: str, policy_id: str) -> None:
    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    match = next((p for p in policies if p["PolicyId"] == policy_id), None)
    if match is not None:
        ssm.delete_resource_policy(
            ResourceArn=resource_arn, PolicyId=policy_id, PolicyHash=match["PolicyHash"]
        )


def _error_code(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy rejects a policy's own prior PolicyHash, made stale by an update, with
    ResourcePolicyNotFoundException naming the resource, policy id and hash; it leaves the policy
    attached under its current hash, and the identical call with that current hash then succeeds."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    param_name = ctx.unique_name("sim2real-respolicy-hash-")
    ssm.put_parameter(
        Name=param_name, Value="v1", Type="String", Tier="Advanced",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))
    resource_arn = ssm.get_parameter(Name=param_name)["Parameter"]["ARN"]

    def _policy_doc(sid: str) -> str:
        return json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": sid,
                    "Effect": "Allow",
                    "Principal": {"AWS": account_id},
                    "Action": "ssm:GetParameter",
                    "Resource": resource_arn,
                }
            ],
        })

    put_resp = ssm.put_resource_policy(ResourceArn=resource_arn, Policy=_policy_doc("sim2realShareV1"))
    policy_id = put_resp["PolicyId"]
    stale_hash = put_resp["PolicyHash"]
    ctx.on_cleanup(lambda: _delete_policy_if_present(ssm, resource_arn, policy_id))

    # Updating the same policy in place advances its hash, making stale_hash obsolete.
    updated = ssm.put_resource_policy(
        ResourceArn=resource_arn, Policy=_policy_doc("sim2realShareV2"),
        PolicyId=policy_id, PolicyHash=stale_hash,
    )
    current_hash = updated["PolicyHash"]
    assert current_hash != stale_hash, "update must advance the policy hash"

    code, message = _error_code(
        lambda: ssm.delete_resource_policy(
            ResourceArn=resource_arn, PolicyId=policy_id, PolicyHash=stale_hash
        )
    )
    assert code == "ResourcePolicyNotFoundException", code
    assert message == (
        f"Resource policy for resource {resource_arn} with policy ID {policy_id} and policy "
        f"hash {stale_hash} does not exist"
    ), message

    # The rejected delete left the current policy attached, under its current hash.
    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    assert len(policies) == 1, policies
    assert policies[0]["PolicyId"] == policy_id, policies
    assert policies[0]["PolicyHash"] == current_hash, policies

    # Restore: the identical call with the current hash succeeds.
    ssm.delete_resource_policy(
        ResourceArn=resource_arn, PolicyId=policy_id, PolicyHash=current_hash
    )
    remaining = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    assert remaining == [], remaining


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
