"""put-resource-policy-second-policy-without-policy-id-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-second-policy-without-policy-id-rejected"
GROUP = "concurrency"
SERVICES = ["ssm"]


def _policy_doc(sid: str, account_id: str, resource_arn: str) -> str:
    return json.dumps(
        {
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
        }
    )


def _error(fn):
    """Call fn() and return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A parameter accepts only one attached resource policy at a time: a second
    PutResourcePolicy with no PolicyId is refused ValidationException while the first
    policy is still attached, and the same no-PolicyId call succeeds once it is gone."""
    ssm = ctx.client("ssm")
    account_id = ctx.account

    param_name = "/" + ctx.unique_name("sim2real-respolicy-second-")
    ssm.put_parameter(
        Name=param_name,
        Value="v1",
        Type="String",
        Tier="Advanced",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))
    resource_arn = ssm.get_parameter(Name=param_name)["Parameter"]["ARN"]

    put_a = ssm.put_resource_policy(
        ResourceArn=resource_arn, Policy=_policy_doc("sim2realPolicyA", account_id, resource_arn)
    )
    policy_id_a = put_a["PolicyId"]
    ctx.on_cleanup(lambda: _delete_if_present(ssm, resource_arn, policy_id_a))

    err = _error(
        lambda: ssm.put_resource_policy(
            ResourceArn=resource_arn, Policy=_policy_doc("sim2realPolicyB", account_id, resource_arn)
        )
    )
    assert err["Code"] == "ValidationException", err
    assert err.get("Message") == (
        f"Resource policy for parameter {resource_arn} already exists"
    ), f"unexpected message: {err.get('Message')!r}"

    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    assert [p["PolicyId"] for p in policies] == [policy_id_a], (
        f"a refused second PutResourcePolicy changed the attached policies: {policies}"
    )

    hash_a = policies[0]["PolicyHash"]
    ssm.delete_resource_policy(ResourceArn=resource_arn, PolicyId=policy_id_a, PolicyHash=hash_a)

    # With no policy attached, the identical no-PolicyId call now succeeds.
    put_b = ssm.put_resource_policy(
        ResourceArn=resource_arn, Policy=_policy_doc("sim2realPolicyB", account_id, resource_arn)
    )
    policy_id_b = put_b["PolicyId"]
    ctx.on_cleanup(lambda: _delete_if_present(ssm, resource_arn, policy_id_b))
    policies_after = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    assert [p["PolicyId"] for p in policies_after] == [policy_id_b], (
        f"after policy A was removed, GetResourcePolicies returned {policies_after}, "
        f"expected only the newly attached policy B ({policy_id_b})"
    )


def _delete_if_present(ssm, resource_arn: str, policy_id: str) -> None:
    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    match = next((p for p in policies if p["PolicyId"] == policy_id), None)
    if match is not None:
        try:
            ssm.delete_resource_policy(
                ResourceArn=resource_arn, PolicyId=policy_id, PolicyHash=match["PolicyHash"]
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourcePolicyNotFoundException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
