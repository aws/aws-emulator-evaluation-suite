"""resource-policy-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy attaches a policy retrievable via GetResourcePolicies and
    removable via DeleteResourcePolicy; once removed, the same (PolicyId,
    PolicyHash) no longer identifies any stored policy revision."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    param_name = ctx.unique_name("sim2real-respolicy-param-")
    ssm.put_parameter(
        Name=param_name,
        Value="v1",
        Type="String",
        Tier="Advanced",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))
    resource_arn = ssm.get_parameter(Name=param_name)["Parameter"]["ARN"]

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realShare",
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "ssm:GetParameter",
                "Resource": resource_arn,
            }
        ],
    }
    put_resp = ssm.put_resource_policy(ResourceArn=resource_arn, Policy=json.dumps(policy_doc))
    policy_id = put_resp["PolicyId"]
    policy_hash = put_resp["PolicyHash"]
    ctx.on_cleanup(lambda: _delete_policy_if_present(ssm, resource_arn, policy_id))

    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    match = next((p for p in policies if p["PolicyId"] == policy_id), None)
    assert match is not None, policies
    assert match["PolicyHash"] == policy_hash, (match["PolicyHash"], policy_hash)

    ssm.delete_resource_policy(
        ResourceArn=resource_arn, PolicyId=policy_id, PolicyHash=policy_hash
    )

    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    assert not any(p["PolicyId"] == policy_id for p in policies), policies

    # The deleted (PolicyId, PolicyHash) pair no longer identifies any stored
    # revision: the identical delete call that just succeeded now fails.
    code, message = _client_error(
        lambda: ssm.delete_resource_policy(
            ResourceArn=resource_arn, PolicyId=policy_id, PolicyHash=policy_hash
        )
    )
    assert code == "ResourcePolicyNotFoundException", code
    assert message == (
        f"Resource policy for resource {resource_arn} with policy ID {policy_id} and policy hash "
        f"{policy_hash} does not exist"
    ), message


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_policy_if_present(ssm, resource_arn: str, policy_id: str) -> None:
    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    match = next((p for p in policies if p["PolicyId"] == policy_id), None)
    if match is not None:
        ssm.delete_resource_policy(
            ResourceArn=resource_arn, PolicyId=policy_id, PolicyHash=match["PolicyHash"]
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
