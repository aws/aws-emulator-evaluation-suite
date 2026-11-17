"""put-resource-policy-update-with-stale-hash-rejected-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-update-with-stale-hash-rejected-not-found"
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
    """PutResourcePolicy with the hash of a policy version a later update already replaced
    is refused ResourcePolicyNotFoundException and leaves the current version untouched;
    the same call with the current hash applies."""
    ssm = ctx.client("ssm")
    account_id = ctx.account

    param_name = "/" + ctx.unique_name("sim2real-respolicy-conflict-")
    ssm.put_parameter(
        Name=param_name,
        Value="v1",
        Type="String",
        Tier="Advanced",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))
    resource_arn = ssm.get_parameter(Name=param_name)["Parameter"]["ARN"]

    put_v1 = ssm.put_resource_policy(
        ResourceArn=resource_arn, Policy=_policy_doc("sim2realShareV1", account_id, resource_arn)
    )
    policy_id = put_v1["PolicyId"]
    hash_v1 = put_v1["PolicyHash"]
    ctx.on_cleanup(lambda: _delete_current_policy(ssm, resource_arn, policy_id))

    # Positive control: updating in place with the current hash succeeds and advances the hash.
    put_v2 = ssm.put_resource_policy(
        ResourceArn=resource_arn,
        Policy=_policy_doc("sim2realShareV2", account_id, resource_arn),
        PolicyId=policy_id,
        PolicyHash=hash_v1,
    )
    assert put_v2["PolicyId"] == policy_id, (
        f"update changed the policy id from {policy_id!r} to {put_v2['PolicyId']!r}"
    )
    hash_v2 = put_v2["PolicyHash"]
    assert hash_v2 != hash_v1, "updating the policy content left the hash unchanged"

    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    stored = next((p for p in policies if p["PolicyId"] == policy_id), None)
    assert stored is not None, f"policy {policy_id} missing from GetResourcePolicies: {policies}"
    assert stored["PolicyHash"] == hash_v2, (
        f"expected the stored hash to be the update's {hash_v2!r}, got {stored['PolicyHash']!r}"
    )
    assert json.loads(stored["Policy"])["Statement"][0]["Sid"] == "sim2realShareV2", (
        f"stored policy content did not reflect the update: {stored['Policy']}"
    )

    # Negative: hash_v1 now names an obsolete version. The update is refused, and the stored
    # version stays at v2.
    err = _error(
        lambda: ssm.put_resource_policy(
            ResourceArn=resource_arn,
            Policy=_policy_doc("sim2realShareV3Rejected", account_id, resource_arn),
            PolicyId=policy_id,
            PolicyHash=hash_v1,
        )
    )
    assert err["Code"] == "ResourcePolicyNotFoundException", err
    assert err.get("Message") == (
        f"Resource policy for resource {resource_arn} with policy ID {policy_id} and policy "
        f"hash {hash_v1} does not exist"
    ), f"unexpected message: {err.get('Message')!r}"

    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    stored = next((p for p in policies if p["PolicyId"] == policy_id), None)
    assert stored is not None, policies
    assert stored["PolicyHash"] == hash_v2, (
        f"a refused stale-hash update changed the stored hash to {stored['PolicyHash']!r}"
    )
    assert json.loads(stored["Policy"])["Statement"][0]["Sid"] == "sim2realShareV2", (
        f"a refused stale-hash update changed the stored content: {stored['Policy']}"
    )

    # The identical call with the current hash succeeds.
    put_v3 = ssm.put_resource_policy(
        ResourceArn=resource_arn,
        Policy=_policy_doc("sim2realShareV3", account_id, resource_arn),
        PolicyId=policy_id,
        PolicyHash=hash_v2,
    )
    assert put_v3["PolicyId"] == policy_id, put_v3
    assert put_v3["PolicyHash"] not in (hash_v1, hash_v2), (
        f"the accepted update did not advance the hash past {hash_v2!r}"
    )


def _delete_current_policy(ssm, resource_arn: str, policy_id: str) -> None:
    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    match = next((p for p in policies if p["PolicyId"] == policy_id), None)
    if match is not None:
        ssm.delete_resource_policy(
            ResourceArn=resource_arn, PolicyId=policy_id, PolicyHash=match["PolicyHash"]
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
