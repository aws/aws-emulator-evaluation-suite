"""resource-policy-hash-mismatch-delete-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-hash-mismatch-delete-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]


def _poll_until_visible(ssm, resource_arn: str, policy_id: str, attempts: int = 10, delay: float = 1.5):
    """PutResourcePolicy's write may not be immediately visible to
    GetResourcePolicies/DeleteResourcePolicy; poll until the policy shows up."""
    for _ in range(attempts):
        policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
        if any(p["PolicyId"] == policy_id for p in policies):
            return policies
        time.sleep(delay)
    return ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]


def _client_error_retrying(fn, transient_codes, attempts: int = 10, delay: float = 1.5):
    """Retry while fn fails with a transient code; return the first other error (code, message).

    An unexpected success raises rather than returning a sentinel."""
    last = None
    for _ in range(attempts):
        try:
            result = fn()
        except ClientError as e:
            last = (e.response["Error"]["Code"], e.response["Error"].get("Message"))
            if last[0] not in transient_codes:
                return last
            time.sleep(delay)
        else:
            raise AssertionError(f"expected rejection but call succeeded: {result!r}")
    return last


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy with a stale PolicyHash is refused ResourcePolicyNotFoundException and
    leaves the policy attached; the correct hash deletes it, and a repeat of that is refused."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    param_name = "/" + ctx.unique_name("sim2real-respolicy-hashmismatch-")

    ssm.put_parameter(
        Name=param_name,
        Value="secret-value",
        Type="String",
        Tier="Advanced",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def _delete_parameter():
        try:
            ssm.delete_parameter(Name=param_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ParameterNotFound":
                raise

    ctx.on_cleanup(_delete_parameter)

    param_arn = ssm.get_parameter(Name=param_name)["Parameter"]["ARN"]
    # PutResourcePolicy rejects a principal account that does not exist, so share with this one.
    account_id = sts.get_caller_identity()["Account"]
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "sim2real-share",
                    "Effect": "Allow",
                    "Principal": {"AWS": account_id},
                    "Action": "ssm:GetParameter",
                    "Resource": param_arn,
                }
            ],
        }
    )

    put_resp = ssm.put_resource_policy(ResourceArn=param_arn, Policy=policy_doc)
    policy_id = put_resp["PolicyId"]
    correct_hash = put_resp["PolicyHash"]
    _poll_until_visible(ssm, param_arn, policy_id)

    def _delete_policy_best_effort():
        try:
            for p in ssm.get_resource_policies(ResourceArn=param_arn)["Policies"]:
                try:
                    ssm.delete_resource_policy(
                        ResourceArn=param_arn, PolicyId=p["PolicyId"], PolicyHash=p["PolicyHash"]
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                        "ResourceNotFoundException",
                        "ResourcePolicyNotFoundException",
                    ):
                        raise
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ResourceNotFoundException",
                "ResourcePolicyNotFoundException",
            ):
                raise

    ctx.on_cleanup(_delete_policy_best_effort)

    stale_hash = correct_hash[::-1] if correct_hash[::-1] != correct_hash else correct_hash + "x"
    code, message = _client_error_retrying(
        lambda: ssm.delete_resource_policy(
            ResourceArn=param_arn, PolicyId=policy_id, PolicyHash=stale_hash
        ),
        transient_codes=set(),
    )
    assert code == "ResourcePolicyNotFoundException", code
    assert message == (
        f"Resource policy for resource {param_arn} with policy ID {policy_id} and policy hash "
        f"{stale_hash} does not exist"
    ), message

    still_there = ssm.get_resource_policies(ResourceArn=param_arn)["Policies"]
    assert any(p["PolicyId"] == policy_id for p in still_there), still_there

    # Positive control: deleting with the correct hash succeeds.
    ssm.delete_resource_policy(ResourceArn=param_arn, PolicyId=policy_id, PolicyHash=correct_hash)
    remaining = ssm.get_resource_policies(ResourceArn=param_arn)["Policies"]
    assert all(p["PolicyId"] != policy_id for p in remaining), remaining

    redelete_code, redelete_message = _client_error_retrying(
        lambda: ssm.delete_resource_policy(
            ResourceArn=param_arn, PolicyId=policy_id, PolicyHash=correct_hash
        ),
        transient_codes=set(),
    )
    assert redelete_code == "ResourcePolicyNotFoundException", redelete_code
    assert redelete_message == (
        f"Resource policy for resource {param_arn} with policy ID {policy_id} and policy hash "
        f"{correct_hash} does not exist"
    ), redelete_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
