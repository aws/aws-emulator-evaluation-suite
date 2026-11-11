"""delete-resource-policy-unknown-policy-id-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-unknown-policy-id-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy with a never-issued PolicyId fails with ResourcePolicyNotFoundException
    and leaves the attached policy intact; the real PolicyId and hash then delete it.
    """
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    param_name = ctx.unique_name("sim2real-respolicy-unknownid-")
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
    real_policy_id = put_resp["PolicyId"]
    real_hash = put_resp["PolicyHash"]
    ctx.on_cleanup(lambda: _delete_policy_if_present(ssm, resource_arn, real_policy_id))

    bogus_policy_id = "ResourcePolicy-00000000-0000-0000-0000-000000000000"
    assert bogus_policy_id != real_policy_id, (bogus_policy_id, real_policy_id)

    code, message = _error(
        lambda: ssm.delete_resource_policy(
            ResourceArn=resource_arn, PolicyId=bogus_policy_id, PolicyHash=real_hash
        )
    )
    assert code == "ResourcePolicyNotFoundException", code
    assert message == (
        f"Resource policy for resource {resource_arn} with policy ID {bogus_policy_id} "
        f"and policy hash {real_hash} does not exist"
    ), message

    # Positive control: the real policy is untouched by the rejected call, and can
    # be deleted with its correct PolicyId + PolicyHash.
    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    match = next((p for p in policies if p["PolicyId"] == real_policy_id), None)
    assert match is not None, policies
    assert match["PolicyHash"] == real_hash, (match["PolicyHash"], real_hash)

    ssm.delete_resource_policy(ResourceArn=resource_arn, PolicyId=real_policy_id, PolicyHash=real_hash)
    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    assert not any(p["PolicyId"] == real_policy_id for p in policies), policies


def _delete_policy_if_present(ssm, resource_arn: str, policy_id: str) -> None:
    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    match = next((p for p in policies if p["PolicyId"] == policy_id), None)
    if match is not None:
        ssm.delete_resource_policy(
            ResourceArn=resource_arn, PolicyId=policy_id, PolicyHash=match["PolicyHash"]
        )


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
